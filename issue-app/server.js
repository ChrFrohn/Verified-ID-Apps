const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { ConfidentialClientApplication } = require('@azure/msal-node');
const { DefaultAzureCredential } = require('@azure/identity');
const { Client } = require('@microsoft/microsoft-graph-client');
const { AuthenticationProvider } = require('@microsoft/microsoft-graph-client');
require('dotenv').config();

// Graph client needs a custom auth provider since we're using client credentials
class CustomAuthProvider {
    constructor(accessTokenProvider) {
        this.accessTokenProvider = accessTokenProvider;
    }

    async getAccessToken() {
        return await this.accessTokenProvider();
    }
}

const app = express();
const port = process.env.PORT || 3000;

app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
    next();
});

// Parse the Azure Easy Auth headers that get injected by App Service
function parseEasyAuthUser(req) {
    try {
        const clientPrincipal = req.headers['x-ms-client-principal'];
        
        if (!clientPrincipal) {
            return null;
        }
        
        const decodedPrincipal = JSON.parse(Buffer.from(clientPrincipal, 'base64').toString('utf-8'));
        
        console.log('✅ Easy Auth user detected:', {
            userId: decodedPrincipal.userId,
            userDetails: decodedPrincipal.userDetails,
            identityProvider: decodedPrincipal.identityProvider || decodedPrincipal.auth_typ
        });
        
        const claims = decodedPrincipal.claims || [];
        
        const findClaim = (claimType) => {
            const claim = claims.find(c => c.typ === claimType);
            return claim ? claim.val : null;
        };
        
        return {
            userId: decodedPrincipal.userId,
            userDetails: decodedPrincipal.userDetails,
            identityProvider: decodedPrincipal.identityProvider || decodedPrincipal.auth_typ,
            name: findClaim('name') || decodedPrincipal.userDetails,
            email: findClaim('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress') ||
                   findClaim('email') ||
                   findClaim('preferred_username') ||
                   decodedPrincipal.userDetails,
            givenName: findClaim('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname') ||
                      findClaim('given_name'),
            surname: findClaim('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname') ||
                    findClaim('family_name'),
            userPrincipalName: findClaim('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name') ||
                              findClaim('upn') ||
                              decodedPrincipal.userDetails,
            isAuthenticated: true
        };
        
    } catch (error) {
        console.error('❌ Error parsing Easy Auth header:', error.message);
        return null;
    }
}

// Block requests that don't have valid Easy Auth headers
function requireEasyAuth(req, res, next) {
    const user = parseEasyAuthUser(req);
    
    if (!user) {
        return res.status(401).json({ 
            error: 'Authentication required',
            message: 'Please sign in through Azure App Service authentication'
        });
    }
    
    req.easyAuthUser = user;
    next();
}

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }));

console.log(`Starting Issue Credential App on port: ${port}`);

// Make sure we have all the config we need before starting
const requiredEnvVars = [
    'AZURE_CLIENT_ID',
    'AZURE_CLIENT_SECRET', 
    'AZURE_TENANT_ID',
    'DID_AUTHORITY',
    'CREDENTIAL_MANIFEST',
    'CREDENTIAL_TYPE'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingVars);
    process.exit(1);
}

console.log('✅ All required environment variables are configured');
console.log(`🎫 Credential type configured: ${process.env.CREDENTIAL_TYPE}`);

// PIN code length can be configured, default to 4 digits
let pinCodeLength = 4;
if (process.env.ISSUANCE_PIN_CODE_LENGTH) {
    pinCodeLength = parseInt(process.env.ISSUANCE_PIN_CODE_LENGTH);
    if (isNaN(pinCodeLength) || pinCodeLength < 0 || pinCodeLength > 6) {
        console.warn(`⚠️  Invalid PIN length, using default 4`);
        pinCodeLength = 4;
    }
}

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

// Request store for tracking issuance requests
const requestStore = new Map();

// Get access token for Microsoft Request API
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

// Set up Graph client to fetch user data
async function getGraphClient() {
    try {
        const accessTokenProvider = async () => {
            const clientCredentialRequest = {
                scopes: ["https://graph.microsoft.com/.default"]
            };
            const response = await pca.acquireTokenByClientCredential(clientCredentialRequest);
            return response.accessToken;
        };

        const authProvider = new CustomAuthProvider(accessTokenProvider);
        return Client.initWithMiddleware({ authProvider });
    } catch (error) {
        console.error('Error creating Graph client:', error);
        throw new Error(`Failed to create Graph client: ${error.message}`);
    }
}

// Pull user details from Microsoft Graph
async function getUserProfile(userPrincipalName) {
    try {
        const graphClient = await getGraphClient();
        const user = await graphClient.api(`/users/${userPrincipalName}`).get();
        
        return {
            displayName: user.displayName,
            givenName: user.givenName,
            surname: user.surname,
            mail: user.mail || user.userPrincipalName,
            jobTitle: user.jobTitle || "Employee",
            preferredLanguage: user.preferredLanguage || "en-US",
            userPrincipalName: user.userPrincipalName,
            photo: null
        };
    } catch (error) {
        console.error('Error fetching user profile from Graph:', error);
        throw new Error(`Failed to fetch user profile: ${error.message}`);
    }
}

// Try to get the user's profile photo in various sizes
async function getUserPhoto(userPrincipalName) {
    try {
        const graphClient = await getGraphClient();
        const photoSizes = ['240x240', '120x120', '96x96', '64x64', '48x48'];
        let photo = null;
        
        for (const size of photoSizes) {
            try {
                photo = await graphClient.api(`/users/${userPrincipalName}/photos/${size}/$value`).get();
                break;
            } catch (sizeError) {
                continue;
            }
        }
        
        if (!photo) {
            photo = await graphClient.api(`/users/${userPrincipalName}/photo/$value`).get();
        }
        
        if (photo) {
            let buffer;
            
            if (photo instanceof Buffer) {
                buffer = photo;
            } else if (photo && typeof photo.arrayBuffer === 'function') {
                const arrayBuffer = await photo.arrayBuffer();
                buffer = Buffer.from(arrayBuffer);
            } else if (photo instanceof ArrayBuffer) {
                buffer = Buffer.from(photo);
            } else {
                buffer = Buffer.from(photo);
            }
            
            const base64Photo = buffer.toString('base64');
            const encodedPhoto = encodeURIComponent(base64Photo);
            
            console.log(`📸 Using real user photo from Microsoft Graph (${buffer.length} bytes)`);
            return encodedPhoto;
        } else {
            throw new Error('No photo data received');
        }
        
    } catch (error) {
        console.log('❌ Error fetching photo for user %s: %s', userPrincipalName, error.message);
        return null;
    }
}

// Build the credential issuance request
async function createIssuanceRequest(userData, req = null) {
    const client_api_request_endpoint = `${msIdentityHostName}verifiableCredentials/createIssuanceRequest`;
    
    try {
        const accessToken = await getAccessToken();
        const requestId = uuidv4();

        const issuanceRequest = {
            includeQRCode: true,
            callback: {
                url: `${process.env.APP_URL}/api/request-callback`,
                state: requestId,
                headers: {
                    "api-key": "verifiedid-api-key"
                }
            },
            authority: process.env.DID_AUTHORITY,
            registration: {
                clientName: process.env.CLIENT_NAME || "Microsoft Entra Verified ID"
            },
            type: process.env.CREDENTIAL_TYPE,
            manifest: process.env.CREDENTIAL_MANIFEST,
            claims: {
                displayName: userData.displayName || `${userData.firstName || userData.givenName || "Employee"} ${userData.lastName || userData.surname || "User"}`,
                givenName: userData.firstName || userData.givenName || "Employee",
                surname: userData.lastName || userData.surname || "User",
                mail: userData.email || userData.mail || "user@company.com",
                jobTitle: userData.jobTitle || "Employee",
                preferredLanguage: userData.preferredLanguage || "en-US",
                userPrincipalName: userData.userPrincipalName || userData.email || userData.mail || "user@company.com",
                revocationId: userData.revocationId || uuidv4(),
                photo: userData.photo || null
            }
        };

        // Add a PIN code if we're configured to use one
        if (pinCodeLength > 0) {
            const min = Math.pow(10, pinCodeLength - 1);
            const max = Math.pow(10, pinCodeLength) - 1;
            const pinCode = Math.floor(Math.random() * (max - min + 1)) + min;
            
            issuanceRequest.pin = {
                value: pinCode.toString(),
                length: pinCodeLength
            };
            
            console.log(`🔐 Generated ${pinCodeLength}-digit PIN: ${pinCode}`);
        }

        console.log('📤 Making issuance request to:', client_api_request_endpoint);
        
        const response = await axios.post(
            client_api_request_endpoint,
            issuanceRequest,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        // Store request for tracking
        requestStore.set(requestId, {
            type: 'issuance',
            status: 'request_created',
            data: response.data,
            userData: userData,
            pin: issuanceRequest.pin ? issuanceRequest.pin.value : null,
            created: new Date()
        });

        console.log('✅ Issuance request created successfully');
        return {
            requestId: requestId,
            url: response.data.url,
            expiry: response.data.expiry,
            qrCode: response.data.qrCode,
            pin: issuanceRequest.pin ? issuanceRequest.pin.value : null
        };

    } catch (error) {
        console.error('❌ Error creating issuance request:', error.message);
        if (error.response) {
            console.error('Error response:', error.response.data);
        }
        throw new Error(`Failed to create issuance request: ${error.message}`);
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

// Serve static files
app.use(express.static('public'));

// Routes

app.get('/', (req, res) => {
    res.sendFile('index.html', { root: 'public' });
});

app.get('/api/user', requireEasyAuth, async (req, res) => {
    try {
        const easyAuthUser = req.easyAuthUser;
        
        let userProfile;
        try {
            const userPrincipalName = easyAuthUser.userPrincipalName || easyAuthUser.email || easyAuthUser.userDetails;
            userProfile = await getUserProfile(userPrincipalName);
            console.log('✅ Retrieved user profile from Microsoft Graph for /api/user');
        } catch (profileError) {
            console.warn('⚠️ Could not retrieve full profile from Graph, using Easy Auth data');
            userProfile = {
                displayName: easyAuthUser.name || 'Unknown User',
                mail: easyAuthUser.email || 'No email',
                jobTitle: 'Employee',
                userPrincipalName: easyAuthUser.userPrincipalName || easyAuthUser.email
            };
        }
        
        res.json({
            user: userProfile,
            authenticated: true
        });
    } catch (error) {
        console.error('❌ Error in /api/user:', error);
        res.status(500).json({
            error: 'Failed to load user information',
            message: error.message
        });
    }
});

app.post('/api/issue-credential', requireEasyAuth, async (req, res) => {
    try {
        const user = req.easyAuthUser;
        
        console.log(`🎫 Issuing credential for user: ${user.userDetails}`);
        
        let userProfile;
        try {
            userProfile = await getUserProfile(user.userPrincipalName || user.email);
            console.log('✅ Retrieved user profile from Microsoft Graph');
        } catch (profileError) {
            console.warn('⚠️ Could not retrieve full profile, using Easy Auth data');
            userProfile = {
                displayName: user.name,
                givenName: user.givenName || user.name?.split(' ')[0],
                surname: user.surname || user.name?.split(' ').slice(1).join(' '),
                mail: user.email,
                jobTitle: "Employee",
                preferredLanguage: "en-US",
                userPrincipalName: user.userPrincipalName || user.email
            };
        }

        // Try to get user photo
        let userPhoto = null;
        try {
            userPhoto = await getUserPhoto(user.userPrincipalName || user.email);
            if (userPhoto) {
                userProfile.photo = userPhoto;
                console.log('✅ Retrieved user photo from Microsoft Graph');
            }
        } catch (photoError) {
            console.log('⚠️ Could not retrieve user photo, using default');
        }

        const issuanceResult = await createIssuanceRequest(userProfile, req);
        
        res.json({
            success: true,
            requestId: issuanceResult.requestId,
            url: issuanceResult.url,
            expiry: issuanceResult.expiry,
            qrCode: issuanceResult.qrCode,
            pin: issuanceResult.pin,
            message: 'Credential issuance request created successfully'
        });

    } catch (error) {
        console.error('❌ Error in issue-credential endpoint:', error.message);
        res.status(500).json({
            success: false,
            error: error.message,
            message: 'Failed to create credential issuance request'
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
        pin: request.pin
    });
});

// Callback endpoint for Microsoft Request API
app.post('/api/request-callback', (req, res) => {
    const requestId = req.body.state;
    const code = req.body.code;
    
    console.log(`📞 Callback received for request: ${requestId}, code: ${code}`);
    
    const request = requestStore.get(requestId);
    if (request) {
        request.status = code;
        request.updated = new Date();
        requestStore.set(requestId, request);
        
        console.log(`✅ Updated request ${requestId} status to: ${code}`);
    }
    
    res.status(200).json({ message: 'Callback received' });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        app: 'issue-credential',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Start server
app.listen(port, () => {
    console.log(`🚀 Issue Credential App listening on port ${port}`);
    console.log(`🔐 Easy Auth integration enabled - authentication required for all credential operations`);
});
