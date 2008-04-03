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
package org.sakaiproject.captcha.impl;

import net.tanesha.recaptcha.ReCaptcha;
import net.tanesha.recaptcha.ReCaptchaFactory;
import net.tanesha.recaptcha.ReCaptchaResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sakaiproject.captcha.api.CaptchaService;
import org.sakaiproject.captcha.exceptions.FieldsNotDefinedException;
import org.sakaiproject.component.api.ServerConfigurationService;

public abstract class ReCaptchaServiceImpl implements CaptchaService {

	private static Log log = LogFactory.getLog(ReCaptchaServiceImpl.class);
	
	private String recaptchaPublicKey;
	private String recaptchaPrivateKey;
	private boolean recaptchaEnabled = false;

	protected abstract ServerConfigurationService serverConfigurationService();
	
	public void init() {		
		// Get captcha private and public keys
		recaptchaPublicKey = serverConfigurationService().getString("recaptcha.public-key");
		recaptchaPrivateKey = serverConfigurationService().getString("recaptcha.private-key");
		
		recaptchaEnabled = serverConfigurationService().getBoolean("recaptcha.enabled", false) && (recaptchaPublicKey != null && recaptchaPrivateKey != null 
				&& recaptchaPublicKey.trim().length() > 0 && recaptchaPrivateKey.trim().length() > 0);
	}
	
	public boolean checkCaptchaResponse(String remoteAddr, String challenge, String response) throws FieldsNotDefinedException {
		
		if (recaptchaEnabled) {
			if (remoteAddr == null || remoteAddr.trim().length() == 0)
				throw new FieldsNotDefinedException("Remote address");
			if (challenge == null || challenge.trim().length() == 0)
				throw new FieldsNotDefinedException("Challenge");
			if (response == null || response.trim().length() == 0)
				throw new FieldsNotDefinedException("Response");
			
			ReCaptcha recaptcha = ReCaptchaFactory.newSecureReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
			
			ReCaptchaResponse captchaResponse = recaptcha.checkAnswer(remoteAddr, challenge, response);
			
			if (log.isDebugEnabled() && captchaResponse.getErrorMessage() != null)
				log.debug("ReCaptcha server responded with following error message: " + captchaResponse.getErrorMessage());
					
			return captchaResponse.isValid();
		}
		
		return false;
	}

	public String createCaptchaMarkup(String errorMessage, String theme, Integer tabIndex) {
		if (recaptchaEnabled) {
			// Grab a new recaptcha object
			ReCaptcha recaptcha = ReCaptchaFactory.newSecureReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
				
			// write the captcha
			return recaptcha.createRecaptchaHtml(errorMessage, theme, tabIndex);
		}
		
		return "";
	}
	
	public boolean isEnabled() {
		return recaptchaEnabled;
	}

}
