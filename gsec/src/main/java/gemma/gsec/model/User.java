/*
 * The Gemma project.
 * 
 * Copyright (c) 2006-2012 University of British Columbia
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
 * A user of the software system, who is authenticated.
 */
public abstract class User extends PersonImpl implements SecuredNotChild {

    /**
     * Constructs new instances of {@link User}.
     */
    public static final class Factory {
        /**
         * Constructs a new instance of {@link User}.
         */
        public static User newInstance() {
            return new UserImpl();
        }

    }

    private String userName;

    private String password;

    private String passwordHint;

    private Boolean enabled;

    private String signupToken;

    private java.util.Date signupTokenDatestamp;

    // TODO
    // private Collection<JobInfo> jobs = new java.util.HashSet<JobInfo>();

    // private Collection<UserQuery> savedQueries = new java.util.HashSet<UserQuery>();

    /**
     * 
     */
    public Boolean getEnabled() {
        return this.enabled;
    }

    /**
     * 
     */
    /*
     * public Collection<JobInfo> getJobs() { return this.jobs; }
     */

    /**
     * 
     */
    public String getPassword() {
        return this.password;
    }

    /**
     * 
     */
    public String getPasswordHint() {
        return this.passwordHint;
    }

    /**
    *
     */
    /*
     * public Collection<UserQuery> getSavedQueries() { return this.savedQueries; }
     */

    /**
     * 
     */
    public String getSignupToken() {
        return this.signupToken;
    }

    /**
     * 
     */
    public java.util.Date getSignupTokenDatestamp() {
        return this.signupTokenDatestamp;
    }

    /**
     * 
     */
    public String getUserName() {
        return this.userName;
    }

    public void setEnabled( Boolean enabled ) {
        this.enabled = enabled;
    }

    /*
     * public void setJobs( Collection<JobInfo> jobs ) { this.jobs = jobs; }
     */

    public void setPassword( String password ) {
        this.password = password;
    }

    public void setPasswordHint( String passwordHint ) {
        this.passwordHint = passwordHint;
    }

    /*
     * public void setSavedQueries( Collection<UserQuery> savedQueries ) { this.savedQueries = savedQueries; }
     */

    public void setSignupToken( String signupToken ) {
        this.signupToken = signupToken;
    }

    public void setSignupTokenDatestamp( java.util.Date signupTokenDatestamp ) {
        this.signupTokenDatestamp = signupTokenDatestamp;
    }

    public void setUserName( String userName ) {
        this.userName = userName;
    }

}