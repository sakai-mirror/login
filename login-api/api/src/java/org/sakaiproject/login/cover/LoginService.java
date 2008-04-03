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
package org.sakaiproject.login.cover;

import org.sakaiproject.component.cover.ComponentManager;
import org.sakaiproject.login.api.LoginCredentials;
import org.sakaiproject.login.exceptions.LoginCredentialsNotDefinedException;

public class LoginService {

	/**
	 * Access the component instance: special cover only method.
	 * 
	 * @return the component instance.
	 */
	public static org.sakaiproject.login.api.LoginService getInstance()
	{
		if (ComponentManager.CACHE_COMPONENTS)
		{
			if (m_instance == null)
				m_instance = (org.sakaiproject.login.api.LoginService) ComponentManager
						.get(org.sakaiproject.login.api.LoginService.class);
			return m_instance;
		}
		else
		{
			return (org.sakaiproject.login.api.LoginService) ComponentManager
					.get(org.sakaiproject.login.api.LoginService.class);
		}
	}

	private static org.sakaiproject.login.api.LoginService m_instance = null;
	
	public static int PROTECTION_LEVEL_NONE = org.sakaiproject.login.api.LoginService.PROTECTION_LEVEL_NONE;
	public static int PROTECTION_LEVEL_IP_ADDRESS = org.sakaiproject.login.api.LoginService.PROTECTION_LEVEL_IP_ADDRESS;
	public static int PROTECTION_LEVEL_IP_USER_PASS = org.sakaiproject.login.api.LoginService.PROTECTION_LEVEL_IP_USER_PASS;

	
	public static boolean checkLoginCredentials(LoginCredentials credentials) 
		throws LoginCredentialsNotDefinedException {
		org.sakaiproject.login.api.LoginService service = getInstance();
		if (service == null) return false;

		return service.checkLoginCredentials(credentials);
	}
	
	public static String getPenaltyMarkup() {
		org.sakaiproject.login.api.LoginService service = getInstance();
		if (service == null) return null;

		return service.getPenaltyMarkup();
	}
	
	public static int getProtectionLevel() {
		org.sakaiproject.login.api.LoginService service = getInstance();
		if (service == null) return PROTECTION_LEVEL_NONE;

		return service.getProtectionLevel();
	}

	public static boolean hasFailedLogin(String remoteAddress) {
		org.sakaiproject.login.api.LoginService service = getInstance();
		if (service == null) return true;

		return service.hasFailedLogin(remoteAddress);
	}

	public static void setFailedLogin(LoginCredentials credentials) {
		org.sakaiproject.login.api.LoginService service = getInstance();
		if (service == null) return;

		service.setFailedLogin(credentials);
	}
	
	public static void setSuccessfulLogin(LoginCredentials credentials) {
		org.sakaiproject.login.api.LoginService service = getInstance();
		if (service == null) return;

		service.setSuccessfulLogin(credentials);
	}
	
}
