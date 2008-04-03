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
package org.sakaiproject.login.api;

import org.sakaiproject.login.exceptions.LoginCredentialsNotDefinedException;

public interface LoginService {
		
	public static final int PROTECTION_LEVEL_NONE = 0;
	public static final int PROTECTION_LEVEL_IP_ADDRESS = 1;
	public static final int PROTECTION_LEVEL_IP_USER_PASS = 2;
	
	public boolean checkLoginCredentials(LoginCredentials credentials) throws LoginCredentialsNotDefinedException;
	
	public String getPenaltyMarkup();
	
	public int getProtectionLevel();
	
	public boolean hasFailedLogin(String remoteAddress);
	
	public void setFailedLogin(LoginCredentials credentials);
	
	public void setSuccessfulLogin(LoginCredentials credentials);
	
}
