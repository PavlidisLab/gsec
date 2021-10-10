/*
 * The gemma-mda project
 *
 * Copyright (c) 2013 University of British Columbia
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
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashSet;

import org.springframework.security.acls.domain.IdentityUnavailableException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import gemma.gsec.model.Securable;

/**
 * TODO Document Me
 *
 * @author Paul
 * @version $Id: AclObjectIdentity.java,v 1.1 2013/09/14 16:55:18 paul Exp $
 */
public class AclObjectIdentity implements ObjectIdentity {
    /**
     *
     */
    private static final long serialVersionUID = -6715898560226971244L;

    // this should be ord
    private Collection<AclEntry> entries = new HashSet<>();

    private Boolean entriesInheriting = false;

    // of this objectidentity
    private Long id;

    // of the entity
    private Serializable identifier;

    private AclSid ownerSid;

    private AclObjectIdentity parentObject;

    private String type;

    public AclObjectIdentity() {
    }

    /**
     * @param javaType
     * @param identifier
     */
    public AclObjectIdentity( Class<? extends Securable> javaType, Long identifier ) {
        this.type = javaType.getName();
        this.identifier = identifier;
    }

    /**
     * If the object is a proxy, its superclass must be the correct one to give the OBJECT_CLASS (type) in the ACL
     * tables. For polymorphic classes this will be a problem if the method returns the superclass, so use fetch all
     * properties. Example: PhenotypeAssociationDao. See chapter 19.1.3 of the Hibernate documentation for an
     * explanation about polymorphic classes and proxies.
     *
     * @param object
     */
    public AclObjectIdentity( Object object ) {

        Class<?> typeClass = ClassUtils.getUserClass( object.getClass() );

        type = typeClass.getName();

        Object result;
        try {
            Method method = typeClass.getMethod( "getId" );
            result = method.invoke( object );
        } catch ( Exception e ) {
            throw new IdentityUnavailableException( "Could not extract identity from object " + object, e );
        }

        Assert.notNull( result, "getId() is required to return a non-null value" );
        Assert.isInstanceOf( Serializable.class, result, "Getter must provide a return value of type Serializable" );
        this.identifier = ( Serializable ) result;

    }

    public AclObjectIdentity( String type, Serializable identifier ) {
        this();
        this.type = type;
        this.identifier = identifier;
    }

    @Override
    public boolean equals( Object o ) {
        if ( o == null ) return false;
        if ( o == this ) return true;
        if ( !( o instanceof ObjectIdentity ) ) return false;

        ObjectIdentity oi = ( ObjectIdentity ) o;

        return ( this.type.equals( oi.getType() ) && this.identifier.equals( oi.getIdentifier() ) );

    }

    public Collection<AclEntry> getEntries() {
        return entries;
    }

    public Boolean getEntriesInheriting() {
        return entriesInheriting;
    }

    public Long getId() {
        return id;
    }

    @Override
    public Serializable getIdentifier() {
        return this.identifier;
    }

    public AclSid getOwnerSid() {
        return ownerSid;
    }

    public AclObjectIdentity getParentObject() {
        return parentObject;
    }

    @Override
    public String getType() {
        return this.type;
    }

    /**
     * Important so caching operates properly.
     *
     * @return the hash
     */
    @Override
    public int hashCode() {
        int code = 31;
        code ^= this.type.hashCode();
        code ^= this.identifier.hashCode();
        return code;
    }

    public void setEntries( Collection<AclEntry> entries ) {
        this.entries = entries;
    }

    public void setEntriesInheriting( Boolean entriesInheriting ) {
        this.entriesInheriting = entriesInheriting;
    }

    public void setId( Long id ) {
        this.id = id;
    }

    public void setIdentifier( Serializable identifier ) {
        this.identifier = identifier;
    }

    public void setOwnerSid( Sid ownerSid ) {
        this.ownerSid = ( AclSid ) ownerSid;
    }

    public void setParentObject( AclObjectIdentity parentObject ) {
        assert parentObject != this && !this.equals( parentObject );
        this.parentObject = parentObject;
    }

    public void setType( String type ) {
        this.type = type;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append( this.getClass().getName() ).append( "[" );
        sb.append( "Type: " ).append( this.type );
        sb.append( "; Identifier: " ).append( this.identifier ).append( "]" );

        return sb.toString();
    }

}
