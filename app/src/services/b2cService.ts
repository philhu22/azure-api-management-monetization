import qs from 'qs';

// https://docs.microsoft.com/en-us/azure/active-directory-b2c/authorization-code-flow

export class B2CService {

    initialized = false;

    serverUrl: string = process.env.SERVER_URL;
    b2cBaseUrl: string = process.env.AZURE_B2C_TENANT_BASE_URL;
    b2cAuthorizationEndpoint: string = process.env.AZURE_B2C_AUTHORIZE_ENDPOINT;
    b2cTokenEndpoint: string = process.env.AZURE_B2C_TOKEN_ENDPOINT;

    b2cClientId: string = process.env.AZURE_B2C_APIM_DEV_PORTAL_APP_ID;
    b2cClientSecret: string = process.env.AZURE_B2C_APIM_DEV_PORTAL_APP_SECRET;
    b2cSignUpOrSignInPolicy: string = process.env.AZURE_B2C_APIM_SIGNUP_SIGNIN_POLICY;

    /** Get the authorization code url */
    public getAuthCodeUri(): string {
        const uri: string = this.b2cAuthorizationEndpoint
            .replace('{base_url}', this.b2cBaseUrl)
            .replace('{policy}', this.b2cSignUpOrSignInPolicy)
            .replace('{client_id}', this.b2cClientId)
            .replace('{redirect_uri}', this.serverUrl + '/authcode');

        return uri;
    }

    /** Get an access token after acquiring an authorization code */
    public async getAccessToken(authCode:string): Promise<[string, any]> {
        await this.initialize();

        const axios = require('axios');

        let idToken: string = '';
        let error: any = null;

        const data = {
            grant_type: 'authorization_code',
            client_id: this.b2cClientId,
            client_secret: this.b2cClientSecret,
            scope: 'openid',
            redirect_uri: this.serverUrl + '/authcode',
            code: authCode
        };

        const options = {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            data: qs.stringify(data),
            url: this.b2cTokenEndpoint
                .replace('{base_url}', this.b2cBaseUrl)
                .replace('{policy}', this.b2cSignUpOrSignInPolicy)
        };

        const sendPostRequest = async () => {
            try {
                const resp = await axios(options);
                idToken = resp.data.id_token as string;
            } catch (err) {
                error = err;
            }
        };

        await sendPostRequest();

        return [idToken, error];
    }




    private async initialize() {
        if (!this.initialized) {

            this.initialized = true;
        }
    }
}