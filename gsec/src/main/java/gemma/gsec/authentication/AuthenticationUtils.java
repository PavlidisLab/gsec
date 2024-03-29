/*
 * The Gemma project
 *
 * Copyright (c) 2006 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package gemma.gsec.authentication;

import gemma.gsec.AuthorityConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;
import java.util.List;

/**
 * Common methods for authenticating users.
 *
 * @author pavlidis
 * @version $Id: AuthenticationUtils.java,v 1.7 2013/09/21 15:10:54 paul Exp $
 */
public class AuthenticationUtils {

    public static final String ANONYMOUS_AUTHENTICATION_KEY = "key";
    private static final Log log = LogFactory.getLog( AuthenticationUtils.class.getName() );

    /**
     * This is only needed for situations outside the web context.
     *
     * @param manager
     */
    public static void anonymousAuthenticate( AuthenticationManager manager ) {
        log.debug( "No authentication object in context, providing anonymous authentication" );
        List<GrantedAuthority> gas = new ArrayList<>();

        /*
         * "GROUP_ANONYMOUS" is defined in applicationContext-springSecurity.
         */
        gas.add( new SimpleGrantedAuthority( AuthorityConstants.ANONYMOUS_GROUP_AUTHORITY ) );

        /*
         * "anonymousUser" is defined in org.springframework.security.config.http.AuthenticationConfigBuilder (but is
         * also configurable...).
         */
        Authentication authRequest = new AnonymousAuthenticationToken( ANONYMOUS_AUTHENTICATION_KEY,
            AuthorityConstants.ANONYMOUS_USER_NAME, gas );
        authRequest = manager.authenticate( authRequest );
        SecurityContextHolder.getContext().setAuthentication( authRequest );
    }

}
