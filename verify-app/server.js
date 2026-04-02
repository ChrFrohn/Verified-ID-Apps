const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { ConfidentialClientApplication } = require('@azure/msal-node');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
    next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }));

console.log(`Starting Verify Credential App on port: ${port}`);

// Make sure we have all the config we need
const requiredEnvVars = [
    'AZURE_CLIENT_ID',
    'AZURE_CLIENT_SECRET', 
    'AZURE_TENANT_ID',
    'DID_AUTHORITY',
    'CREDENTIAL_TYPE',
    'APP_URL'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingVars);
    process.exit(1);
}

console.log('✅ All required environment variables are configured');
console.log(`🔍 Credential type for verification: ${process.env.CREDENTIAL_TYPE}`);

const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;

const msalConfig = {
    auth: {
        clientId: clientId,
        clientSecret: clientSecret,
        authority: `https://login.microsoftonline.com/${tenantId}`
    }
};

const pca = new ConfidentialClientApplication(msalConfig);
const msIdentityHostName = "https://verifiedid.did.msidentity.com/v1.0/";

// Request store for tracking verification requests
// Keep track of pending verification requests
const requestStore = new Map();

async function getAccessToken() {
    try {
        const clientCredentialRequest = {
            scopes: ["3db474b9-6a0c-4840-96ac-1fceb342124f/.default"]
        };

        const response = await pca.acquireTokenByClientCredential(clientCredentialRequest);
        return response.accessToken;
    } catch (error) {
        console.error('Error acquiring access token:', error);
        throw new Error(`Failed to acquire access token: ${error.errorCode || error.message}`);
    }
}

// Build the credential verification request
async function createVerificationRequest(options = {}) {
    const client_api_request_endpoint = `${msIdentityHostName}verifiableCredentials/createPresentationRequest`;
    
    try {
        const accessToken = await getAccessToken();
        const requestId = uuidv4();

        const verificationRequest = {
            includeQRCode: true,
            callback: {
                url: `${process.env.APP_URL}/api/verification-callback`,
                state: requestId,
                headers: {
                    "api-key": "verifiedid-api-key"
                }
            },
            authority: process.env.DID_AUTHORITY,
            registration: {
                clientName: process.env.CLIENT_NAME || "Microsoft Entra Verified ID Verifier",
                purpose: process.env.PURPOSE || "To verify your credential status"
            },
            includeReceipt: true,
            requestedCredentials: [
                {
                    type: process.env.CREDENTIAL_TYPE,
                    purpose: process.env.PURPOSE || "To verify your credential status",
                    acceptedIssuers: [process.env.DID_AUTHORITY],
                    configuration: {
                        validation: {
                            allowRevoked: false,
                            validateLinkedDomain: true
                        }
                    }
                }
            ]
        };

        // Enable face verification if requested
        if (options.includeFaceCheck) {
            verificationRequest.requestedCredentials[0].configuration.validation.faceCheck = {
                sourcePhotoClaimName: "photo",
                matchConfidenceThreshold: 70
            };
            console.log('🔍 Face verification enabled with 70% confidence threshold');
        }

        console.log('📤 Making verification request to:', client_api_request_endpoint);
        
        const response = await axios.post(
            client_api_request_endpoint,
            verificationRequest,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        // Store request for tracking
        requestStore.set(requestId, {
            type: 'verification',
            status: 'request_created',
            data: response.data,
            options: options,
            created: new Date()
        });

        console.log('✅ Verification request created successfully');
        return {
            requestId: requestId,
            url: response.data.url,
            expiry: response.data.expiry,
            qrCode: response.data.qrCode
        };

    } catch (error) {
        console.error('❌ Error creating verification request:', error.message);
        if (error.response) {
            console.error('Error response:', error.response.data);
        }
        throw new Error(`Failed to create verification request: ${error.message}`);
    }
}

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});
app.use(apiLimiter);

app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile('index.html', { root: 'public' });
});

app.post('/api/verify-credential', async (req, res) => {
    try {
        const { includeFaceCheck = false } = req.body;
        
        console.log(`🔍 Creating verification request (Face Check: ${includeFaceCheck ? 'enabled' : 'disabled'})`);
        
        const verificationResult = await createVerificationRequest({ 
            includeFaceCheck: includeFaceCheck 
        });
        
        res.json({
            success: true,
            requestId: verificationResult.requestId,
            url: verificationResult.url,
            expiry: verificationResult.expiry,
            qrCode: verificationResult.qrCode,
            faceCheckEnabled: includeFaceCheck,
            message: 'Credential verification request created successfully'
        });

    } catch (error) {
        console.error('❌ Error in verify-credential endpoint:', error.message);
        res.status(500).json({
            success: false,
            error: error.message,
            message: 'Failed to create credential verification request'
        });
    }
});

// Request status endpoint
app.get('/api/request-status/:requestId', (req, res) => {
    const requestId = req.params.requestId;
    const request = requestStore.get(requestId);
    
    if (!request) {
        return res.status(404).json({
            success: false,
            error: 'Request not found'
        });
    }
    
    res.json({
        success: true,
        requestId: requestId,
        status: request.status,
        type: request.type,
        created: request.created,
        verifiedCredential: request.verifiedCredential || null,
        faceCheckResult: request.faceCheckResult || null
    });
});

// Verification callback endpoint for Microsoft Request API
app.post('/api/verification-callback', (req, res) => {
    const requestId = req.body.state;
    const code = req.body.code;
    
    console.log(`📞 Verification callback received for request: ${requestId}, code: ${code}`);
    
    const request = requestStore.get(requestId);
    if (request) {
        request.status = code;
        request.updated = new Date();
        
        // Handle successful verification
        if (code === 'presentation_verified') {
            if (req.body.verifiedCredentialsData && req.body.verifiedCredentialsData.length > 0) {
                const credentialData = req.body.verifiedCredentialsData[0];
                request.verifiedCredential = {
                    type: credentialData.type,
                    issuer: credentialData.issuer,
                    claims: credentialData.claims,
                    credentialSubject: credentialData.credentialSubject
                };
                
                // Extract face check results if available
                if (credentialData.faceCheck) {
                    request.faceCheckResult = {
                        faceCheckPassed: credentialData.faceCheck.faceCheckPassed,
                        confidence: credentialData.faceCheck.confidence
                    };
                    console.log(`✅ Face verification result: ${credentialData.faceCheck.faceCheckPassed ? 'PASSED' : 'FAILED'} (${credentialData.faceCheck.confidence}% confidence)`);
                }
                
                console.log('✅ Credential verification successful:', {
                    type: credentialData.type,
                    issuer: credentialData.issuer,
                    subject: credentialData.credentialSubject?.displayName || 'Unknown'
                });
            }
        }
        
        requestStore.set(requestId, request);
        console.log(`✅ Updated verification request ${requestId} status to: ${code}`);
    }
    
    res.status(200).json({ message: 'Verification callback received' });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        app: 'verify-credential',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Start server
app.listen(port, () => {
    console.log(`🚀 Verify Credential App listening on port ${port}`);
    console.log(`🌐 Public access enabled - no authentication required for credential verification`);
});
