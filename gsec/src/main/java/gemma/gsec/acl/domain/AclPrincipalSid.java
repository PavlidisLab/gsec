/*
 * The gemma-mda project
 *
 * Copyright (c) 2013 University of British Columbia
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
package gemma.gsec.acl.domain;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.Objects;

/**
 * @author Paul
 * @version $Id: AclPrincipalSid.java,v 1.1 2013/09/14 16:55:18 paul Exp $
 */
public class AclPrincipalSid extends AclSid {

    private static final long serialVersionUID = -4679911678447417301L;
    private String principal;

    public AclPrincipalSid() {
    }

    public AclPrincipalSid( Authentication authentication ) {
        Assert.notNull( authentication, "Authentication required" );
        Assert.notNull( authentication.getPrincipal(), "Principal required" );

        if ( authentication.getPrincipal() instanceof UserDetails ) {
            this.principal = ( ( UserDetails ) authentication.getPrincipal() ).getUsername();
        } else {
            this.principal = authentication.getPrincipal().toString();
        }
    }

    public AclPrincipalSid( String principal ) {
        super();
        this.principal = principal;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal( String principal ) {
        this.principal = principal;
    }

    @Override
    public int hashCode() {
        return Objects.hash( principal );
    }

    @Override
    public boolean equals( Object object ) {
        if ( !( object instanceof AclPrincipalSid ) ) {
            return false;
        }

        if ( this == object ) return true;

        // Delegate to getPrincipal() to perform actual comparison (both should be identical)
        return ( ( AclPrincipalSid ) object ).getPrincipal().equals( this.getPrincipal() );
    }

    @Override
    public String toString() {
        return "AclPrincipalSid[" + this.principal + "]";
    }
}
