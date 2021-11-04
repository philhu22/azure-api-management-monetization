import express from "express";
import crypto from "crypto";
import querystring, { stringify } from "querystring";
import { ApimService } from "../services/apimService";
import { BillingService } from "../services/billingService";
import { B2CService } from "../services/b2cService";
import jwt_decode, { JwtPayload } from "jwt-decode";
import { UserCollection } from "@azure/arm-apimanagement/esm/models";


export const register = (app: express.Application, billingService: BillingService) => {
    const apimService = new ApimService();
    const b2cService = new B2CService();

    /** Delegated sign up/in, sign out and subscription creation for APIM */
    app.get("/apim-delegation", async (req, res) => {
        const operation = req.query.operation as string;
        const errorMessage = req.query.errorMessage as string;

        let isValid: boolean;
        switch (operation) {
            case "SignUp":
            case "SignIn":
                const signUpSignInRequest: SignUpSignInRequest = {
                    operation,
                    returnUrl: req.query.returnUrl as string,
                    salt: req.query.salt as string,
                    sig: req.query.sig as string,
                }

                isValid = validateSignUpSignInRequest(signUpSignInRequest);

                if (!isValid) {
                    res.status(401);
                    return;
                }

                if (process.env.AUTHENTICATION_PROVIDER === 'Username_and_password') {

                    if (operation === "SignIn") {
                        res.render("sign-in", { title: 'Sign in', signUpSignInRequest, errorMessage });
                    }
                    else if (operation === "SignUp") {
                        res.render("sign-up", { title: 'Sign up', signUpSignInRequest, errorMessage });
                    }
                    else if (operation === "ChangePassword") {
                        return reportError(req, res, "Change Password is not implemented");
                    }
                }
                else if (process.env.AUTHENTICATION_PROVIDER === 'Azure_Active_Directory_B2C') {
                    // Get an authorization code from Azure B2C
                    const uri: string = b2cService.getAuthCodeUri();
                    res.redirect(uri);
                }

                break;
            case "SignOut":
                const returnUrl = req.query.returnUrl as string;
                const redirectUrl = process.env.APIM_DEVELOPER_PORTAL_URL; // + returnUrl;
                res.redirect(redirectUrl);
                break;
            case "Subscribe":
                const subscribeRequest: SubscriptionRequest = {
                    operation,
                    productId: req.query.productId as string,
                    userId: req.query.userId as string,
                    salt: req.query.salt as string,
                    sig: req.query.sig as string,
                };

                isValid = validateSubscribeRequest(subscribeRequest);

                if (!isValid) {
                    res.status(401);
                    return;
                }

                const product = await apimService.getProduct(subscribeRequest.productId);

                res.render("subscribe", { subscribeRequest, product, title: "Subscribe" });
                break;
            case "Unsubscribe":
                const unsubscribeRequest: SubscriptionRequest = {
                    operation,
                    subscriptionId: req.query.subscriptionId as string,
                    salt: req.query.salt as string,
                    sig: req.query.sig as string,
                };

                isValid = validateUnsubscribeRequest(unsubscribeRequest);

                if (!isValid) {
                    res.status(401);
                    return;
                }

                await apimService.updateSubscriptionState(unsubscribeRequest.subscriptionId, "cancelled");
                await billingService.unsubscribe(unsubscribeRequest.subscriptionId);

                res.render("unsubscribe", { unsubscribeRequest, title: "Unsubscribe" });

            case "ChangePassword":
                const ChangePasswordRequest: OtherRequest = {
                    operation,
                    userId: req.query.userId as string,
                    salt: req.query.salt as string,
                    sig: req.query.sig as string,
                };

                isValid = validateOtherRequest(ChangePasswordRequest);

                if (!isValid) {
                    res.status(401);
                    return;
                }

                if (process.env.AUTHENTICATION_PROVIDER === 'Username_and_password') {
                        return reportError(req, res, "Change Password is not implemented");
                }
                else if (process.env.AUTHENTICATION_PROVIDER === 'Azure_Active_Directory_B2C') {
                    // Get an authorization code from Azure B2C
                    const uri: string = b2cService.getAuthCodeUri();
                    res.redirect(uri);
                }

                break;

            case "ChangeProfile":
            case "CloseAccount":
            case "Renew":
                // Not implemented
                res.status(501);
                break;
            default:
                res.status(400);
                break;
        }
    });

    /** Create a subscription for the user. This includes validating the request, retrieving the user, and redirecting them to checkout. On successful checkout, the subscription will be created. */
    app.post("/subscribe", async (req, res) => {
        const subscribeRequest: SubscriptionRequest = {
            operation: req.body.operation as string,
            productId: req.body.productId as string,
            userId: req.body.userId as string,
            salt: req.body.salt as string,
            sig: req.body.sig as string,
        };

        const isValid = validateSubscribeRequest(subscribeRequest);

        if (!isValid) {
            res.status(401);
            return;
        }

        const subscriptionName = req.body.subscriptionName as string;

        const user = await apimService.getUser(subscribeRequest.userId);

        const redirectQuery = querystring.stringify({
            operation: subscribeRequest.operation,
            userId: subscribeRequest.userId,
            productId: subscribeRequest.productId,
            subscriptionName,
            salt: subscribeRequest.salt,
            sig: subscribeRequest.sig,
            userEmail: user.email
        });

        res.redirect("/checkout?" + redirectQuery);
    });

    /** Checkout, using redirect to specific payment provider view */
    app.get("/checkout", async (req, res) => {
        const operation = req.query.operation as string;
        const userId = req.query.userId as string;
        const productId = req.query.productId as string;
        const subscriptionName = req.query.subscriptionName as string;
        const salt = req.query.salt as string;
        const sig = req.query.sig as string;
        const userEmail = req.query.userEmail as string;

        const subscribeRequest: SubscriptionRequest = {
            operation,
            productId,
            userId,
            salt,
            sig
        }

        const isValid = validateSubscribeRequest(subscribeRequest);

        if (!isValid) {
            res.status(401);
            return;
        }

        res.render(`checkout-${process.env.PAYMENT_PROVIDER.toLowerCase()}`, { subscribeRequest, subscriptionName, userEmail, title: "Checkout" });
    });

    /** Obtain a B2C access token after aquiring an authorization code, then find the user by decoding the
     *  access token, then get an APIM SAS token before signin to APIM
     */
    app.get("/authcode", async (req, res) => {
        const errorMessage = req.query.errorMessage as string;
        const authCode: string = req.query.code as string;

        if (errorMessage) {
            return reportError(req, res, "Invalid credentials");
        }

        // get a b2c access code (jwt token)
        const [idToken, error] = await b2cService.getAccessToken(authCode);
        if (error) {
            console.log(error);
            return reportError(req, res, "Invalid authorization code");
        }

        // decode jwt payload
        const decoded = jwt_decode<JwtPayloadB2C>(idToken);
        const email = decoded.emails[0] as string;

        // find that user in APIM
        const users: UserCollection = await apimService.getUserByEmail(email);

        let userId: string = '';
        if (users == null || users.count === 0) {
            try {
                const password: string = 'fr%q/=/j/X/O7cba)G G';
                const firstName: string = 'Toto';
                const lastName: string = 'Leheros';
                await apimService.createUser(email, password, firstName, lastName);
                const newUser = await ApimService.authenticateUser(email, password);
                if (newUser.authenticated) {
                    userId = newUser.userId as string;
                } else {
                    console.log(error);
                    return reportError(req, res, "Could not authenticate you!");
                }

            }
            catch (error) {
                console.log(error);
                return reportError(req, res, "Could not create a new user for you!");
            }
        }
        else {
            userId = users[0].name;
        }

        // get the APIM user shared access token
        const { value: token } = await apimService.getSharedAccessToken(userId);

        // Finally... APIM signin
        const redirectQuery = querystring.stringify({
            token,
            returnUrl: '/'
        });

        const redirectUrl = process.env.APIM_DEVELOPER_PORTAL_URL + "/signin-sso?" + redirectQuery;

        res.redirect(redirectUrl);

    });


    /** Sign in user using APIM authentication service */
    app.post("/signIn", async (req, res) => {
        const email = req.body.email as string;
        const password = req.body.password as string;

        const signUpSignInRequest: SignUpSignInRequest = {
            operation: req.body.operation as string,
            returnUrl: req.body.returnUrl as string,
            salt: req.body.salt as string,
            sig: req.body.sig as string,
        }

        const { authenticated, userId } = await ApimService.authenticateUser(email, password);

        if (!authenticated) {
            const query = querystring.stringify({
                errorMessage: "Invalid credentials",
                returnUrl: signUpSignInRequest.returnUrl,
                operation: signUpSignInRequest.operation,
                salt: signUpSignInRequest.salt,
                sig: signUpSignInRequest.sig
            });
            res.redirect('/apim-delegation?' + query);
            return;
        }

        const { value: token } = await apimService.getSharedAccessToken(userId);

        const redirectQuery = querystring.stringify({
            token,
            returnUrl: signUpSignInRequest.returnUrl
        });

        const redirectUrl = process.env.APIM_DEVELOPER_PORTAL_URL + "/signin-sso?" + redirectQuery;

        res.redirect(redirectUrl);
    });

    /** Sign up user by creating a new user via the APIM service */
    app.post("/signUp", async (req, res) => {
        const email = req.body.email as string;
        const password = req.body.password as string;
        const firstName = req.body.firstName as string;
        const lastName = req.body.lastName as string;

        const signUpSignInRequest: SignUpSignInRequest = {
            operation: req.body.operation as string,
            returnUrl: req.body.returnUrl as string,
            salt: req.body.salt as string,
            sig: req.body.sig as string,
        }

        try {
            await apimService.createUser(email, password, firstName, lastName);
        }
        catch (error) {
            const query = querystring.stringify({
                errorMessage: "Invalid credentials",
                returnUrl: signUpSignInRequest.returnUrl,
                operation: signUpSignInRequest.operation,
                salt: signUpSignInRequest.salt,
                sig: signUpSignInRequest.sig
            });
            res.redirect('/apim-delegation?' + query);
            return;
        }

        const { userId } = await ApimService.authenticateUser(email, password);
        const { value: token } = await apimService.getSharedAccessToken(userId);

        const redirectQuery = querystring.stringify({
            token,
            returnUrl: signUpSignInRequest.returnUrl
        })

        const redirectUrl = process.env.APIM_DEVELOPER_PORTAL_URL + "/signin-sso?" + redirectQuery;

        res.redirect(redirectUrl);
    });

    app.get("/success", (req, res) => {
        res.render("success", { title: 'Payment Succeeded' });
    });

    app.get("/fail", (req, res) => {
        const subscribeRequest: SubscriptionRequest = {
            operation: req.query.operation as string,
            productId: req.query.productId as string,
            userId: req.query.userId as string,
            salt: req.query.salt as string,
            sig: req.query.sig as string,
        };

        const subscriptionName = req.query.subscriptionName as string;
        const userEmail = req.query.userEmail as string;

        const checkoutQuery = querystring.stringify({
            operation: subscribeRequest.operation,
            userId: subscribeRequest.userId,
            productId: subscribeRequest.productId,
            salt: subscribeRequest.salt,
            sig: subscribeRequest.sig,
            subscriptionName,
            userEmail
        });

        const checkoutUrl = "/checkout?" + checkoutQuery;

        res.render("fail", { title: 'Payment Failed', checkoutUrl });
    });

    /** Checkout cancelled, redirect to payment cancelled view */
    app.get("/cancel", (req, res) => {
        const subscribeRequest: SubscriptionRequest = {
            operation: req.query.operation as string,
            productId: req.query.productId as string,
            userId: req.query.userId as string,
            salt: req.query.salt as string,
            sig: req.query.sig as string,
        };

        const subscriptionName = req.query.subscriptionName as string;
        const userEmail = req.query.userEmail as string;

        const checkoutQuery = querystring.stringify({
            operation: subscribeRequest.operation,
            userId: subscribeRequest.userId,
            productId: subscribeRequest.productId,
            salt: subscribeRequest.salt,
            sig: subscribeRequest.sig,
            subscriptionName,
            userEmail
        });

        const checkoutUrl = "/checkout?" + checkoutQuery;

        res.render("cancel", { title: 'Payment Cancelled', checkoutUrl });
    });
}

/** Validate request signatures */
/** see  https://github.com/Azure/api-management-developer-portal/issues/1138 */
function validateSignUpSignInRequest(signUpSignInRequest: SignUpSignInRequest): boolean {
    return validateRequest([signUpSignInRequest.salt, signUpSignInRequest.returnUrl], signUpSignInRequest.sig)
}

function validateOtherRequest(otherRequest: OtherRequest): boolean {
    return validateRequest([otherRequest.salt, otherRequest.userId], otherRequest.sig)
}

function validateSubscribeRequest(subscriptionRequest: SubscriptionRequest): boolean {
    return validateRequest([subscriptionRequest.salt, subscriptionRequest.productId, subscriptionRequest.userId], subscriptionRequest.sig)
}

function validateUnsubscribeRequest(subscriptionRequest: SubscriptionRequest): boolean {
    return validateRequest([subscriptionRequest.salt, subscriptionRequest.subscriptionId], subscriptionRequest.sig)
}

function validateRequest(queryParams: string[], expectedSignature: string): boolean {
    const key = process.env.APIM_DELEGATION_VALIDATION_KEY;
    const hmac = crypto.createHmac('sha512', Buffer.from(key, 'base64'));

    const input = queryParams.join('\n');
    const digest = hmac.update(input).digest();

    const calculatedSignature = digest.toString('base64');

    return calculatedSignature === expectedSignature;
}

function reportError(req: any, res: any, message: string) {

    const signUpSignInRequest: SignUpSignInRequest = {
        operation: req.body.operation as string,
        returnUrl: req.body.returnUrl as string,
        salt: req.body.salt as string,
        sig: req.body.sig as string,
    }

    const query = querystring.stringify({
        errorMessage: message,
        returnUrl: signUpSignInRequest.returnUrl,
        operation: signUpSignInRequest.operation,
        salt: signUpSignInRequest.salt,
        sig: signUpSignInRequest.sig
    });

    res.redirect('/apim-delegation?' + query);
    return;
}

/** The returnUrl parameter is used only for SignIn and SignUp */
/** HMAC(salt + '\n' + returnUrl) */
interface SignUpSignInRequest {
    operation: string;
    returnUrl: string;
    salt: string;
    sig: string;
}

/** For CloseAccount, ChangeProfile, ChangePassword, SignOut the userId is used in signature */
/** HMAC(salt + '\n' + userId) */
interface OtherRequest {
    operation: string;
    userId: string;
    salt: string;
    sig: string;
}

interface SubscriptionRequest {
    operation: string;
    productId?: string;
    subscriptionId?: string;
    userId?: string;
    salt: string;
    sig: string;
}

interface JwtPayloadB2C {
    iss?: string;
    sub?: string;
    aud?: string[] | string;
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
    emails?: string[] | string;
}