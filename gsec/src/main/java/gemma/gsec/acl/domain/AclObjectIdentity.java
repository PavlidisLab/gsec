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

import gemma.gsec.model.Securable;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import javax.annotation.Nullable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Implementation of {@link ObjectIdentity}.
 *
 * @author Paul
 * @version $Id: AclObjectIdentity.java,v 1.1 2013/09/14 16:55:18 paul Exp $
 */
public class AclObjectIdentity implements ObjectIdentity {

    private static final long serialVersionUID = -6715898560226971244L;

    // of this objectidentity
    private Long id;

    // of the entity
    private Long identifier;

    private String type;

    private AclSid ownerSid;

    @Nullable
    private AclObjectIdentity parentObject;

    private Set<AclEntry> entries = new HashSet<>();

    private boolean entriesInheriting = false;

    @SuppressWarnings("unused")
    public AclObjectIdentity() {
    }

    public AclObjectIdentity( Class<? extends Securable> javaType, Long identifier ) {
        Assert.notNull( javaType, "The java type must be non-null" );
        Assert.notNull( identifier, "The identifier must be non-null" );
        this.type = javaType.getName();
        this.identifier = identifier;
    }

    /**
     * If the object is a proxy, its superclass must be the correct one to give the OBJECT_CLASS (type) in the ACL
     * tables. For polymorphic classes this will be a problem if the method returns the superclass, so use fetch all
     * properties. Example: PhenotypeAssociationDao. See chapter 19.1.3 of the Hibernate documentation for an
     * explanation about polymorphic classes and proxies.
     */
    public AclObjectIdentity( Securable object ) {
        Assert.notNull( object.getId(), "ID is required to be non-null" );
        Class<?> typeClass = ClassUtils.getUserClass( object.getClass() );
        type = typeClass.getName();
        this.identifier = object.getId();

    }

    public AclObjectIdentity( String type, Long identifier ) {
        this.type = type;
        this.identifier = identifier;
    }

    public Long getId() {
        return id;
    }

    public void setId( Long id ) {
        this.id = id;
    }

    @Override
    public String getType() {
        return this.type;
    }

    public void setType( String type ) {
        this.type = type;
    }

    @Override
    public Long getIdentifier() {
        return this.identifier;
    }

    @SuppressWarnings("unused")
    public void setIdentifier( Long identifier ) {
        this.identifier = identifier;
    }

    public Set<AclEntry> getEntries() {
        return entries;
    }

    @SuppressWarnings("unused")
    public void setEntries( Set<AclEntry> entries ) {
        this.entries = entries;
    }

    public boolean getEntriesInheriting() {
        return entriesInheriting;
    }

    public void setEntriesInheriting( boolean entriesInheriting ) {
        this.entriesInheriting = entriesInheriting;
    }

    public AclSid getOwnerSid() {
        return ownerSid;
    }


    public void setOwnerSid( Sid ownerSid ) {
        this.ownerSid = ( AclSid ) ownerSid;
    }

    @Nullable
    public AclObjectIdentity getParentObject() {
        return parentObject;
    }

    public void setParentObject( @Nullable AclObjectIdentity parentObject ) {
        assert parentObject != this && !this.equals( parentObject );
        this.parentObject = parentObject;
    }

    /**
     * Important so caching operates properly.
     *
     * @return the hash
     */
    @Override
    public int hashCode() {
        return Objects.hash( type, identifier );
    }

    @Override
    public boolean equals( Object o ) {
        if ( o == null ) return false;
        if ( o == this ) return true;
        if ( !( o instanceof ObjectIdentity ) ) return false;
        ObjectIdentity oi = ( ObjectIdentity ) o;
        return ( this.type.equals( oi.getType() ) && this.identifier.equals( oi.getIdentifier() ) );
    }

    @Override
    public String toString() {
        return String.format( "%s[Type: %s; Identifier: %s]", this.getClass().getName(), this.type, this.identifier );
    }
}
