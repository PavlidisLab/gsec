/*
 * The gemma-gsec project
 * 
 * Copyright (c) 2014 University of British Columbia
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

package gemma.gsec.model;

/**
 * TODO Document Me
 * 
 * @author ptan
 * @version $Id$
 */
public interface User extends Describable, Person, SecuredNotChild {

    /**
     * 
     */
    public Boolean getEnabled();

    /**
     * 
     */
    public String getPassword();

    /**
     * 
     */
    public String getPasswordHint();

    /**
     * 
     */
    public String getSignupToken();

    /**
     * 
     */
    public java.util.Date getSignupTokenDatestamp();

    /**
     * 
     */
    public String getUserName();

    public void setEnabled( Boolean enabled );

    public void setPassword( String password );

    public void setPasswordHint( String passwordHint );

    public void setSignupToken( String signupToken );

    public void setSignupTokenDatestamp( java.util.Date signupTokenDatestamp );

    public void setUserName( String userName );
}
