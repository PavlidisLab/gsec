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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

/**
 * Models the acl entry
 *
 * @author paul
 */
public class AclEntry implements AccessControlEntry, Comparable<AclEntry> {

    private static final PermissionFactory permissionFactory = new DefaultPermissionFactory();

    /**
     * The serial version UID of this class. Needed for serialization.
     */
    private static final long serialVersionUID = -4697361841061166973L;

    /**
     * @param entries
     * @param acl to be associated with the AccessControlEntries
     * @return
     */
    final public static List<AccessControlEntry> convert( List<AclEntry> entries, Acl acl ) {
        List<AccessControlEntry> result = new ArrayList<>();
        Collections.sort( entries ); // might be able to avoid...
        for ( AclEntry e : entries ) {
            result.add( e.convert( acl ) );
        }
        return result;
    }

    final private Integer aceOrder = null;

    final private Acl acl = null;

    final private Boolean granting = null;

    final private Long id = null;

    final private Integer mask = null;

    final private Sid sid = null;

    public AclEntry() {
    }

    public AclEntry( Serializable id, Acl acl, Sid sid, Permission permission, boolean granting ) {
        Assert.notNull( acl, "Acl required" );
        Assert.notNull( sid, "Sid required" );
        Assert.notNull( permission, "Permission required" );
        try {
            FieldUtils.writeField( this, "id", id, true );
            FieldUtils.writeField( this, "acl", acl, true );
            FieldUtils.writeField( this, "sid", sid, true );
            FieldUtils.writeField( this, "mask", permission.getMask(), true );
            FieldUtils.writeField( this, "granting", granting, true );
        } catch ( IllegalAccessException e ) {
            e.printStackTrace();
        }

    }

    @Override
    final public int compareTo( AclEntry o ) {
        return this.getAceOrder().compareTo( o.getAceOrder() );
    }

    /**
     * @param acl
     * @return
     */
    final public AccessControlEntry convert( Acl a ) {
        return new AccessControlEntryImpl( this.id, a, this.sid, permissionFactory.buildFromMask( this.mask ),
            this.granting, false, false );
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

        if ( granting == null ) {
            if ( other.granting != null ) return false;
        } else if ( !granting.equals( other.granting ) ) return false;

        if ( mask == null ) {
            if ( other.mask != null ) return false;
        } else if ( !mask.equals( other.mask ) ) return false;
        if ( sid == null ) {
            return other.sid == null;
        } else return sid.equals( other.sid );
    }

    /**
     *
     */
    public Integer getAceOrder() {
        return this.aceOrder;
    }

    @Override
    public Acl getAcl() {
        return this.acl;
    }

    /**
     *
     */
    public java.lang.Boolean getGranting() {
        return this.granting;
    }

    /**
     *
     */
    @Override
    public Long getId() {
        return this.id;
    }

    /**
     *
     */
    public Integer getMask() {
        return this.mask;
    }

    @Override
    public Permission getPermission() {
        return permissionFactory.buildFromMask( mask );
    }

    /**
     *
     */
    @Override
    public Sid getSid() {
        return this.sid;
    }

    /*
     * Note that this does not use the ID, to avoid getting duplicate entries.
     *
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    final public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ( ( granting == null ) ? 0 : granting.hashCode() );
        result = prime * result + ( ( mask == null ) ? 0 : mask.hashCode() );
        result = prime * result + ( ( sid == null ) ? 0 : sid.hashCode() );
        return result;
    }

    @Override
    public boolean isGranting() {
        if ( this.granting == null ) return false;
        return this.granting.booleanValue();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append( "AclEntry[" );
        sb.append( "id: " ).append( this.id ).append( "; " );
        sb.append( "granting: " ).append( this.granting ).append( "; " );
        sb.append( "sid: " ).append( this.sid ).append( "; " );
        sb.append( "permission: " ).append( permissionFactory.buildFromMask( mask ) ).append( "; " );
        sb.append( "]" );

        return sb.toString();
    }

}