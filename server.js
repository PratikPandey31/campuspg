require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const Joi = require('joi');
const morgan = require('morgan');

const app = express();
const port = 3000;

const PAYOMATIX_SECRET_KEY = process.env.PAYOMATIX_SECRET_KEY;
const Campus_BACKEND_URL = process.env.Campus_BACKEND_URL;
const Campus_INTERNAL_SECRET = process.env.Campus_INTERNAL_SECRET;

const PAYOMATIX_API_URL = 'https://admin.payomatix.com/payment/merchant/transaction';

// Security Middleware
app.use(helmet());

// Logging and Body Parsing
app.use(morgan('dev'));
app.use(bodyParser.json()); // Parses application/json bodies

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'], // Add OPTIONS here
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Joi Schema for validating incoming payment requests
const paymentSchema = Joi.object({
    customerEmail: Joi.string().email().required().messages({
        'string.base': 'Customer email must be a string.',
        'string.email': 'Customer email must be a valid email address.',
        'any.required': 'Customer email is required.'
    }),
    userId: Joi.string().required().messages({
        'string.base': 'User ID must be a string.',
        'any.required': 'User ID is required.'
    })
});

// Route to create a payment intent with Payomatix
app.post('/create-payment-intent', async (req, res) => {
    // Validate incoming request body
    const { error, value } = paymentSchema.validate(req.body, { abortEarly: false });
    if (error) {
        console.error('Validation error for /create-payment-intent:', error.details);
        return res.status(400).json({
            success: false,
            message: 'Invalid request data provided.',
            errors: error.details.map(d => d.message)
        });
    }

    const {
        customerEmail,
        userId
    } = value; // 'value' contains the validated and cleaned data

    // Set default values
    const returnUrl = 'http://localhost:5173/studentProfile';
    const currency = 'INR';
    const amount = 1; // You may want to adjust this default amount or make it configurable

    // This allows us to retrieve them when the webhook returns.
    let merchantRef = `payomatix-ref-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    if (userId) {
        merchantRef += `-user_${userId}`;
    }

    // Payomatix return and notify URLs (these need to be public and reachable by Payomatix)
    // Use provided returnUrl or fallback to default
    let finalReturnUrl = returnUrl;
    let notifyUrl = 'https://campuspg.onrender.com/payomatix-webhook'; // This proxy's webhook URL

    try {
        // Construct the payload for the Payomatix API request
        const payomatixRequestBody = JSON.stringify({
            email: customerEmail.trim(),
            amount: amount.toFixed(2), // Ensure two decimal places
            currency: currency.trim(),
            return_url: finalReturnUrl.trim(),
            notify_url: notifyUrl.trim(),
            merchant_ref: merchantRef.trim() // Send the enriched merchantRef
        });

        console.log('--- PAYOMATIX API REQUEST ---');
        console.log('URL:', PAYOMATIX_API_URL);
        console.log('Payload:', payomatixRequestBody);
        console.log('Return URL:', finalReturnUrl);
        console.log('-----------------------------');

        // Make the actual call to Payomatix
        const payomatixResponse = await fetch(PAYOMATIX_API_URL, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Authorization': PAYOMATIX_SECRET_KEY, 
                'Content-Type': 'application/json'
            },
            body: payomatixRequestBody
        });

        const payomatixData = await payomatixResponse.json();

        console.log('Raw Payomatix API response data:', payomatixData);
        console.timeEnd('Payomatix API Call');

        // Handle Payomatix response
        if (payomatixData.responseCode === 300 && payomatixData.status === 'redirect') {
            console.log('--- REDIRECT URL RECEIVED ---');
            console.log('Payomatix API successful response (redirect):', payomatixData);
            console.log('Redirect URL:', payomatixData.redirect_url);
            console.log('-----------------------------');

            if (payomatixData.redirect_url) {
                res.json({
                    success: true,
                    message: 'Payment intent created successfully. Redirect URL received.',
                    redirectUrl: payomatixData.redirect_url,
                    transactionId: payomatixData.merchant_ref || payomatixData.transaction_id
                });
            } else {
                console.warn('Payomatix successful redirect response did not contain "redirect_url":', payomatixData);
                res.status(500).json({
                    success: false,
                    message: 'Payment intent created, but redirection URL was not provided by Payomatix. Please check Payomatix API response format.',
                    payomatixResponse: payomatixData
                });
            }
        } else if (payomatixData.responseCode >= 400 || payomatixData.status === 'validation_error') {
            console.error('Error response from Payomatix API:', payomatixData);
            res.status(payomatixResponse.status || 500).json({
                success: false,
                message: 'Failed to create payment intent with Payomatix.',
                error: payomatixData.response || payomatixData.message || 'Unknown error from Payomatix API.',
                payomatixErrors: payomatixData.errors
            });
        } else {
            console.warn('Unexpected but not explicitly erroneous response from Payomatix API:', payomatixData);
            res.status(500).json({
                success: false,
                message: 'Received an unexpected response from Payomatix API.',
                payomatixResponse: payomatixData
            });
        }

    } catch (error) {
        console.error('Server error during payment intent creation:', error);
        res.status(500).json({
            success: false,
            message: 'An internal server error occurred while processing your payment request.',
            error: error.message
        });
    }
});

// THIS IS THE WEBHOOK ROUTE (Receives webhooks from Payomatix)
app.post('/payomatix-webhook', async (req, res) => {
    console.log('--- WEBHOOK RECEIVED ---');
    console.log('Received Payomatix webhook payload:', JSON.stringify(req.body, null, 2));
    console.log('------------------------');

    // --- IMPORTANT: Webhook Verification (CRITICAL for security) ---
    // Implement this! For production, you MUST verify that this webhook came from Payomatix
    // using their provided signature verification mechanism.
    // Example (conceptual):
    // --- END Webhook Verification ---


    // Extract relevant data from the nested 'data' object of the Payomatix webhook
    const webhookData = req.body.data;

    if (!webhookData) {
        console.error('WEBHOOK ERROR: Payomatix webhook payload is missing the "data" object.', req.body);
        return res.status(400).json({ received: false, message: 'Invalid webhook payload structure: missing data object.' });
    }

    // Destructure the fields exactly as they appear in the `data` object of the webhook payload
    const {
        id: payomatixTransactionId,
        merchant_ref: correlationId, 
        status,
        response: message,
        converted_amount: amount,
        currency,
        email: customerEmail,
        name: customerName,
        phone_no: customerPhone
    } = webhookData;

    let userId = null;

    // Regex to find 'user_...' and 'card_...' patterns
    const userIdMatch = correlationId.match(/-user_([a-zA-Z0-9]+)/); // Adjust regex based on actual ID format

    if (userIdMatch?.[1]) {
        userId = userIdMatch[1];
        console.log(`Extracted userId: ${userId}`);
    }
    // --- END NEW Extraction ---

    // Basic validation for critical fields before forwarding
    if (!correlationId || !payomatixTransactionId || !status || amount === undefined || !currency) {
        console.error('PAYOMATIX BACKEND: Missing critical data after parsing webhook. Cannot forward.');
        console.error('Parsed Data:', { correlationId, payomatixTransactionId, status, amount, currency });
        return res.status(400).json({ received: false, message: 'Missing critical data in webhook payload.' });
    }


    // --- Forwarding the webhook message to Campus Backend ---
    if (Campus_BACKEND_URL && Campus_INTERNAL_SECRET) {
        try {
            const CampusBackendNotificationUrl = `${Campus_BACKEND_URL}/api/health-cards/internal/payment-update`;
            console.log(`Received Payomatix webhook, forwarding to Campus Backend at: ${CampusBackendNotificationUrl}`);

            const forwardPayload = {
                correlationId: correlationId,
                payomatixId: payomatixTransactionId,
                status: status,
                message: message,
                amount: amount,
                currency: currency,
                customerEmail: customerEmail,
                customerName: customerName,
                customerPhone: customerPhone,
                receivedAt: new Date().toISOString(),
                userId: userId, // Will be null if not found in correlationId
            };

            console.log('Forwarding Payload:', JSON.stringify(forwardPayload, null, 2));

            const forwardResponse = await fetch(CampusBackendNotificationUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Internal-Secret': Campus_INTERNAL_SECRET
                },
                body: JSON.stringify(forwardPayload)
            });

            if (forwardResponse.ok) {
                console.log('Webhook successfully forwarded to Campus Backend.');
            } else {
                const errorText = await forwardResponse.text();
                console.error(`Failed to forward webhook to Campus Backend. Status: ${forwardResponse.status}, Response: ${errorText}`);
            }
        } catch (forwardError) {
            console.error('Error forwarding webhook to Campus Backend:', forwardError.message);
        }
    } else {
        console.warn('Campus_BACKEND_URL or Campus_INTERNAL_SECRET not set. Skipping Campus Backend notification.');
    }
    // --- End forwarding logic ---

    // Always send 200 OK back to Payomatix to acknowledge receipt promptly
    res.status(200).json({ received: true, message: 'Webhook received and processed.' });
});

app.listen(port, () => {
    console.log(`Payomatix backend server listening at http://localhost:${port}`);
    console.log('----------------------------------------------------');
    console.log('IMPORTANT NOTES:');
    console.log(`2. Your Secret Key: ${PAYOMATIX_SECRET_KEY ? '****** (loaded)' : 'NOT LOADED! Check .env'}`);
    console.log(`3. Payomatix API URL: ${PAYOMATIX_API_URL}`);
    console.log('4. Ensure your server IPs are whitelisted in Payomatix portal (https://portal.payomatix.com/ip-whitelist)!');
    console.log('5. Implement webhook signature verification in /payomatix-webhook for security (CRITICAL).');
    console.log('6. Use HTTPS for all production traffic (frontend and backend).');
    console.log('----------------------------------------------------');

    if (!PAYOMATIX_SECRET_KEY) {
        console.error('ERROR: Payomatix keys are not loaded from .env! Ensure your .env file is correctly configured.');
    }
}); 