package com.security.server.auth.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

// http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri%20=https://www.manning.com/authorized&code_challenge=D53tOzl7Z9k879RPSe41Jb74Z5mUyrHASVtSe7laS9g&code_challenge_method=S256
// http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://www.manning.com/authorized&code_challenge=9dA-E-XpWCeqovcxCOpxJzPIbdRgJknAjbmkQ8yrvDk&code_challenge_method=S256
public class KeyMaker {
    private static String getVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] code = new byte[32];
        secureRandom.nextBytes(code);
        String codeVerifier = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(code);
        return codeVerifier;
    }

    private static String getChallenge(String verifier) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digested = messageDigest.digest(verifier.getBytes());
        String codeChallenge = Base64.getUrlEncoder()
                .withoutPadding().encodeToString(digested);
        return codeChallenge;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String verifier = getVerifier();
        String challenge = getChallenge(verifier);
        System.out.println("Verifier: " + verifier);
        System.out.println("Challenge: " + challenge);
    }

}
