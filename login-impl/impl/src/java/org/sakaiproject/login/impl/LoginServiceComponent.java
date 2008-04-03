/**********************************************************************************
 * $URL:  $
 * $Id:  $
 ***********************************************************************************
 *
 * Copyright (c) 2008 The Sakai Foundation.
 * 
 * Licensed under the Educational Community License, Version 1.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at
 * 
 *      http://www.opensource.org/licenses/ecl1.php
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 *
 **********************************************************************************/
package org.sakaiproject.login.impl;

import java.util.Map;

import net.sf.ehcache.Cache;
import net.sf.ehcache.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sakaiproject.captcha.api.CaptchaService;
import org.sakaiproject.captcha.exceptions.FieldsNotDefinedException;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.login.api.LoginCredentials;
import org.sakaiproject.login.api.LoginService;
import org.sakaiproject.login.exceptions.LoginCredentialsNotDefinedException;

public abstract class LoginServiceComponent implements LoginService {

	private static final String IDCACHE = "id:";
	private static final String PWCACHE = "pw:";
	private static final String IPCACHE = "ip:";
	private static final String DMCACHE = "dm:";
	
	private static Log log = LogFactory.getLog(LoginServiceComponent.class);

	protected abstract CaptchaService captchaService();
	protected abstract ServerConfigurationService serverConfigurationService();

	private Cache loginContextCache;
	private int protectionLevel;
	
	public void init() {
		protectionLevel = serverConfigurationService().getInt("login.protection-level", LoginService.PROTECTION_LEVEL_NONE);
	}
	
	public boolean checkLoginCredentials(LoginCredentials credentials) throws LoginCredentialsNotDefinedException {
		if (! captchaService().isEnabled())
			return true;
		
		// If we're using recaptchas then check to make sure the recaptcha is accurately 
		// filled in - ensure that we're talking to a real human
		String challengeField = null;
		String responseField = null;
			
		// Grab necessary parameters from parameter map
		Map parameterMap = credentials.getParameterMap();
			
		if (parameterMap != null) {
			String[] challengeFields = (String[])parameterMap.get("recaptcha_challenge_field");
			String[] responseFields = (String[])parameterMap.get("recaptcha_response_field");
		
			if (challengeFields != null && challengeFields.length > 0)
				challengeField = challengeFields[0];
			if (responseFields != null && responseFields.length > 0)
				responseField = responseFields[0];
		}
		
		boolean remoteAddressExists = existsRemoteAddress(credentials.getRemoteAddr());
		boolean multipleAttemptsOnUseridPassword = existsIdentifier(credentials.getIdentifier()) || existsPassword(credentials.getPassword());
		
		// Now, let's verify that this user _needs_ to supply a captcha - does he/she have
		// a failed login? 
		if (remoteAddressExists || multipleAttemptsOnUseridPassword) {
		
			boolean isValid = false;
			try {
				isValid = captchaService().checkCaptchaResponse(credentials.getRemoteAddr(), challengeField, responseField);
			} catch (FieldsNotDefinedException nde) {
				throw new LoginCredentialsNotDefinedException("no challenge/response");
			}
		
			return isValid;
		} 

		return true;
	}
		
	public String getPenaltyMarkup() {
		return captchaService().createCaptchaMarkup("Testing", null, null);
	}
	
	public int getProtectionLevel() {
		if (!captchaService().isEnabled())
			return LoginService.PROTECTION_LEVEL_NONE;
			
		return protectionLevel;
	}
	
	public boolean hasFailedLogin(String remoteAddress) {
		return existsRemoteAddress(remoteAddress);
	}
	
	public boolean hasFailedLogin(String identifier, String password) {
		return existsIdentifier(identifier) || existsPassword(password);
	}
	
	public boolean hasMultipleAttempts(LoginCredentials credentials) {
		if (existsIdentifier(credentials.getIdentifier()))
			log.warn("Id exists: " + credentials.getIdentifier());
		if (existsPassword(credentials.getPassword()))
			log.warn("Pw exists: " + credentials.getPassword());
		if (existsRemoteAddress(credentials.getRemoteAddr()))
			log.warn("Addr exists: " + credentials.getRemoteAddr());
		
		return existsIdentifier(credentials.getIdentifier()) ||
			existsPassword(credentials.getPassword()) ||
			existsRemoteAddress(credentials.getRemoteAddr());
	}
	
	public void setFailedLogin(LoginCredentials credentials) {
		// Note that this behavior of falling through the switch is desired
		switch (getProtectionLevel()) {
		case LoginService.PROTECTION_LEVEL_IP_USER_PASS:
			cacheIdentifier(credentials.getIdentifier());
			cachePassword(credentials.getPassword());
		case LoginService.PROTECTION_LEVEL_IP_ADDRESS:
			cacheRemoteAddress(credentials.getRemoteAddr());
		};
	}
	
	public void setSuccessfulLogin(LoginCredentials credentials) {
		switch (getProtectionLevel()) {
		case LoginService.PROTECTION_LEVEL_IP_USER_PASS:
			uncacheIdentifier(credentials.getIdentifier());
			uncachePassword(credentials.getPassword());
		case LoginService.PROTECTION_LEVEL_IP_ADDRESS:
			uncacheRemoteAddress(credentials.getRemoteAddr());
		};
	}
	
	public Cache getLoginContextCache() {
		return loginContextCache;
	}

	public void setLoginContextCache(Cache loginContextCache) {
		this.loginContextCache = loginContextCache;
	}
	
	private void cacheIdentifier(String identifier) {
		cacheObject(IDCACHE, identifier, identifier);
	}
	
	private void cachePassword(String password) {
		cacheObject(PWCACHE, password, password);
	}
	
	private void cacheRemoteAddress(String remoteAddr) {
		cacheObject(IPCACHE, remoteAddr, remoteAddr);
	}
	
	private void cacheDomain(String domain) {
		cacheObject(DMCACHE, domain, domain);
	}
	
	private void cacheObject(String prefix, String name, Object object) {
		loginContextCache.put(new Element(getKey(prefix, name), object));
	}
	
	private boolean existsIdentifier(String identifier) {
		return existsObject(IDCACHE, identifier);
	}
	
	private boolean existsPassword(String password) {
		return existsObject(PWCACHE, password);
	}
	
	private boolean existsRemoteAddress(String remoteAddr) {
		return existsObject(IPCACHE, remoteAddr);
	}
	
	private boolean existsDomain(String domain) {
		return existsObject(DMCACHE, domain);
	}
	
	private boolean existsObject(String prefix, String name) {
		Element el = loginContextCache.get(getKey(prefix, name));
		
		return el != null;
	}
	
	private void uncacheIdentifier(String identifier) {
		uncacheObject(IDCACHE, identifier);
	}
	
	private void uncachePassword(String password) {
		uncacheObject(PWCACHE, password);
	}
	
	private void uncacheRemoteAddress(String remoteAddr) {
		uncacheObject(IPCACHE, remoteAddr);
	}
	
	private void uncacheDomain(String domain) {
		uncacheObject(DMCACHE, domain);
	}
	
	private void uncacheObject(String prefix, String name) {
		loginContextCache.remove(getKey(prefix, name));
	}
	
	private String getKey(String prefix, String name) {
		return new StringBuilder().append(prefix).append(name).toString();
	}
	
	
}
