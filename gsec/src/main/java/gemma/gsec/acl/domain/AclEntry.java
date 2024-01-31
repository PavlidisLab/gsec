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
package gemma.gsec.acl.domain;

import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.PermissionFactory;

import java.io.Serializable;
import java.util.Objects;

/**
 * Models the acl entry
 *
 * @author paul
 */
public class AclEntry implements Serializable, Comparable<AclEntry> {

    /**
     * The serial version UID of this class. Needed for serialization.
     */
    private static final long serialVersionUID = -4697361841061166973L;

    private static final PermissionFactory permissionFactory = new DefaultPermissionFactory();

    private Long id;

    private AclSid sid;

    private boolean granting;

    private int mask;

    private int aceOrder;

    @SuppressWarnings("unused")
    public AclEntry() {

    }


    public Long getId() {
        return this.id;
    }

    public void setId( Long id ) {
        this.id = id;
    }

    public AclSid getSid() {
        return this.sid;
    }

    public void setSid( AclSid sid ) {
        this.sid = sid;
    }

    public boolean isGranting() {
        return this.granting;
    }

    public void setGranting( boolean granting ) {
        this.granting = granting;
    }

    public int getMask() {
        return mask;
    }

    public void setMask( int mask ) {
        this.mask = mask;
    }

    @SuppressWarnings("unused")
    public int getAceOrder() {
        return aceOrder;
    }

    public void setAceOrder( int aceOrder ) {
        this.aceOrder = aceOrder;
    }

    @Override
    public int compareTo( AclEntry other ) {
        return aceOrder - other.aceOrder;
    }

    /**
     * Note that this does not use the ID, to avoid getting duplicate entries.
     */
    @Override
    final public int hashCode() {
        return Objects.hash( granting, mask, sid );
    }

    /*
     * Note that this does not use the ID, to avoid getting duplicate entries.
     *
     *
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    final public boolean equals( Object obj ) {
        if ( this == obj ) return true;
        if ( obj == null ) return false;
        if ( getClass() != obj.getClass() ) return false;
        AclEntry other = ( AclEntry ) obj;

        if ( granting != other.granting ) {
            return false;
        }

        if ( mask != other.mask ) {
            return false;
        }

        if ( sid == null ) {
            return other.sid == null;
        } else return sid.equals( other.sid );
    }

    @Override
    public String toString() {
        return String.format( "AclEntry[id: %d; granting: %s; sid: %s; permission: %s; ]",
            this.id, this.granting, this.sid, permissionFactory.buildFromMask( mask ) );
    }
}