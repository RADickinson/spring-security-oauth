package com.baeldung.config;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class CustomTokenEnhancer implements TokenEnhancer {

  private static final Logger logger = LoggerFactory.getLogger(CustomTokenEnhancer.class);
  
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
      if (logger.isDebugEnabled()) {
        Exception e = new Exception();
        logger.debug("Stack trace log:",e);
      }
        final Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("organization", authentication.getName() + randomAlphabetic(4));
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        if (logger.isDebugEnabled()) {
          logger.debug("Authentication {}", authentication);
          logger.debug("Access token (value) {} ", accessToken);
          logger.debug("Scopes: {}", accessToken.getScope());
          logger.debug("Expiration: {}", accessToken.getExpiration());
          logger.debug("Expires in: {}", accessToken.getExpiresIn());
          logger.debug("Refresh token: {}", accessToken.getRefreshToken());
          logger.debug("Token type: {}", accessToken.getTokenType());
          logger.debug("Additional info: {}", accessToken.getAdditionalInformation());
        }
        return accessToken;
    }
}
