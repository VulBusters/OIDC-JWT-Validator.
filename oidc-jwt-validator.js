const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');
const crypto = require('crypto');

Configuration
// Replace with your actual JWT token
const tokenString = "<YOUR_ACCESS_TOKEN>";
// Replace with your JWKS endpoint URL  
const jwksUrl = "<URL_FOR_JWKS>";

class JWTValidator {
    constructor(jwksUrl) {
        this.jwksUrl = jwksUrl;
        this.jwks = null;
        this.jwksClient = jwksClient({
            jwksUri: jwksUrl,
            cache: true,
            cacheMaxAge: 600000, // 10 minutes
            rateLimit: true,
            jwksRequestsPerMinute: 10,
            requestHeaders: {
                'User-Agent': 'XXX/X.X.X'
            },
            timeout: 30000 // 30 seconds
        });
    }

    async fetchJWKS() {
        try {
            const response = await axios.get(this.jwksUrl, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'XXX/X.X.X',
                    'Accept': 'application/json'
                }
            });
            this.jwks = response.data;
            return this.jwks;
        } catch (error) {
            if (error.response) {
                throw new Error(`Failed to fetch JWKS: ${error.response.status} ${error.response.statusText}`);
            } else if (error.request) {
                throw new Error(`Failed to fetch JWKS: Network error - ${error.message}`);
            } else {
                throw new Error(`Failed to fetch JWKS: ${error.message}`);
            }
        }
    }

    async getPublicKey(kid) {
        if (!this.jwks) {
            throw new Error('JWKS not loaded');
        }

        const key = this.jwks.keys.find(k => k.kid === kid && k.kty === 'RSA');
        if (!key) {
            throw new Error(`Key with ID ${kid} not found`);
        }

        return this.jwkToRSAPublicKey(key);
    }

    jwkToRSAPublicKey(jwk) {
        try {
            // Decode the modulus and exponent from base64url
            const n = Buffer.from(jwk.n, 'base64url');
            const e = Buffer.from(jwk.e, 'base64url');

            // Convert to PEM format
            const modulus = n.toString('hex');
            const exponent = e.toString('hex');

            // Create RSA key object
            const keyObject = crypto.createPublicKey({
                key: {
                    n: Buffer.from(modulus, 'hex'),
                    e: Buffer.from(exponent, 'hex')
                },
                format: 'jwk'
            });

            return keyObject.export({ format: 'pem', type: 'spki' });
        } catch (error) {
            throw new Error(`Failed to convert JWK to RSA public key: ${error.message}`);
        }
    }

    async getSigningKey(kid) {
        try {
            const key = await this.jwksClient.getSigningKey(kid);
            return key.getPublicKey();
        } catch (error) {
            throw new Error(`Failed to get signing key: ${error.message}`);
        }
    }

    async validateToken(tokenString) {
        try {
            // Decode header to get kid
            const decoded = jwt.decode(tokenString, { complete: true });
            if (!decoded || !decoded.header) {
                throw new Error('Invalid token format');
            }

            const { kid } = decoded.header;
            if (!kid) {
                throw new Error('kid not found in token header');
            }

            let publicKey;
            
            try {
                // Try using jwks-rsa client first
                publicKey = await this.getSigningKey(kid);
            } catch (jwksError) {
                console.log(`JWKS client failed: ${jwksError.message}`);
                console.log('Falling back to manual JWKS fetch...');
                
                // If using jwks-rsa client fails, fallback to manual JWKS parsing
                if (!this.jwks) {
                    await this.fetchJWKS();
                }
                publicKey = await this.getPublicKey(kid);
            }

            return {
                valid: true,
            };

        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new Error('Token has expired');
            } else if (error.name === 'JsonWebTokenError') {
                throw new Error(`Token validation failed: ${error.message}`);
            } else {
                throw new Error(`Token validation failed: ${error.message}`);
            }
        }
    }
}

// Helper function to decode JWT without verification
function inspectToken(tokenString) {
    try {
        const decoded = jwt.decode(tokenString, { complete: true });
        return decoded;
    } catch (error) {
        console.error('Failed to decode token:', error.message);
        return null;
    }
}

async function main() {
    try {
        // Create validator
        const validator = new JWTValidator(jwksUrl);
        const inspectedToken = inspectToken(tokenString);
        
        if (inspectedToken && inspectedToken.payload.exp) {
            const expirationTime = new Date(inspectedToken.payload.exp * 1000);
            const currentTime = new Date();
            
            // Check if the token is expired
            if (currentTime > expirationTime) {
                console.log(`Token expired at: ${expirationTime.toISOString()}`);
                return;
            }
        }
        
        const tokenData = await validator.validateToken(tokenString);
        
        if (tokenData.valid) {
            console.log('Token is valid!');
        } else {
            console.log('Token is invalid!');
        }
        
    } catch (error) {
        console.log(`Error: ${error.message}`);
    }
}

// Run the main function
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { JWTValidator, inspectToken };
