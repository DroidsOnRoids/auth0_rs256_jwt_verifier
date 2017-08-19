# Auth0 JWT (RS256) verification library
[Auth0](https://auth0.com) is web service handling users identities which can be easily plugged
into your application. It provides [SDKs](https://auth0.com/docs) for many languages which enable you to sign up/in users
and returns access token ([JWT](https://jwt.io)) in exchange. Access token can be used then to access your's Web Service.
This gem helps you to [verify](https://auth0.com/docs/api-auth/tutorials/verify-access-token#verify-the-signature)
such access token which has been signed using the RS256 algorithm.
