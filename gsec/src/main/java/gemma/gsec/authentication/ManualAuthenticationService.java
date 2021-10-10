/*
 * The Gemma project
 *
 * Copyright (c) 2012 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package gemma.gsec.authentication;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * @author paul
 * @version $Id: ManualAuthenticationService.java,v 1.4 2014/03/23 17:44:06 paul Exp $
 */
public interface ManualAuthenticationService {

    /**
     * @param username
     * @param password
     * @return
     * @throws AuthenticationException
     */
    Authentication attemptAuthentication( String username, String password )
        throws AuthenticationException;

    /**
     * Provide "anonymous" authentication.
     */
    void authenticateAnonymously();

    void setApplicationContext( ApplicationContext applicationContext ) throws BeansException;

    /**
     * Entry point for non-http request.
     *
     * @param username
     * @param password
     */
    boolean validateRequest( String username, String password );

}