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

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.model.*;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an access control list (ACL) for a domain object. Based on spring-security AclImpl.
 *
 * @author Paul
 * @version $Id: AclImpl.java,v 1.1 2013/09/14 16:55:20 paul Exp $
 */
public class AclImpl implements OwnershipAcl {

    private static final long serialVersionUID = -953242274878593548L;

    private final transient AclAuthorizationStrategy aclAuthorizationStrategy;
    private final List<AclEntry> entries;
    private final AclObjectIdentity objectIdentity;
    private Acl parentAcl;

    /**
     * Full constructor
     *
     * @param objectIdentity           the object identity this ACL relates to (required)
     * @param aclAuthorizationStrategy authorization strategy (required)
     * @param parentAcl                the parent (may be <code>null</code>)
     */
    public AclImpl( AclObjectIdentity objectIdentity, AclAuthorizationStrategy aclAuthorizationStrategy,
        Acl parentAcl ) {
        Assert.notNull( objectIdentity, "Object Identity required" );
        Assert.notNull( aclAuthorizationStrategy, "AclAuthorizationStrategy required" );
        Assert.notNull( objectIdentity.getOwnerSid(), "Owner required" );
        this.objectIdentity = objectIdentity;
        this.entries = new ArrayList<>( objectIdentity.getEntries() );
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.parentAcl = parentAcl; // may be null
    }

    @Override
    public void deleteAce( int aceIndex ) throws NotFoundException {
        aclAuthorizationStrategy.securityCheck( this, AclAuthorizationStrategy.CHANGE_GENERAL );
        verifyAceIndexExists( aceIndex );

        synchronized ( entries ) {
            this.entries.remove( aceIndex );
        }
    }

    @Override
    public boolean equals( Object obj ) {
        if ( obj == null ) return false;
        if ( this == obj ) return true;
        if ( !( obj instanceof AclImpl ) ) return false;

        AclImpl rhs = ( AclImpl ) obj;

        if ( ( this.getId() == null && rhs.getId() == null ) || ( this.getId().equals( rhs.getId() ) ) ) {
            if ( ( this.getOwner() == null && rhs.getOwner() == null ) || this.getOwner().equals( rhs.getOwner() ) ) {
                if ( ( this.objectIdentity == null && rhs.objectIdentity == null )
                    || ( this.objectIdentity.equals( rhs.objectIdentity ) ) ) {
                    if ( ( this.parentAcl == null && rhs.parentAcl == null )
                        || ( this.parentAcl.equals( rhs.parentAcl ) ) ) {

                        // if ( ( this.loadedSids == null && rhs.loadedSids == null ) ) {
                        // return true;
                        // }
                        // if ( this.loadedSids.size() == rhs.loadedSids.size() ) {
                        // for ( int i = 0; i < this.loadedSids.size(); i++ ) {
                        // if ( !this.loadedSids.get( i ).equals( rhs.loadedSids.get( i ) ) ) {
                        // return false;
                        // }
                        // }
                        // return true;
                        // }
                        return this.isEntriesInheriting() == rhs.isEntriesInheriting();
                    }

                }
            }
        }
        return false;
    }

    @Override
    public List<AccessControlEntry> getEntries() {
        // populate the ace_order.
        int i = 0;
        for ( AclEntry e : entries ) {
            e.setAceOrder( i++ );
        }
        return new ArrayList<>( entries );
    }

    @Override
    public Serializable getId() {
        return this.objectIdentity.getId();
    }

    @Override
    public ObjectIdentity getObjectIdentity() {
        return objectIdentity;
    }

    @Override
    public Sid getOwner() {
        return this.objectIdentity.getOwnerSid();
    }

    @Override
    public Acl getParentAcl() {
        return parentAcl;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ( ( this.getId() == null ? 0 : this.getId().hashCode() ) );
        result = prime * result + ( ( objectIdentity == null ) ? 0 : objectIdentity.hashCode() );
        return result;
    }

    @Override
    public void insertAce( int atIndexLocation, Permission permission, Sid sid, boolean granting )
        throws NotFoundException {

        assert this.parentAcl == null;

        aclAuthorizationStrategy.securityCheck( this, AclAuthorizationStrategy.CHANGE_GENERAL );
        Assert.notNull( permission, "Permission required" );
        Assert.notNull( sid, "Sid required" );
        if ( atIndexLocation < 0 ) {
            throw new NotFoundException( "atIndexLocation must be greater than or equal to zero" );
        }
        if ( atIndexLocation > this.entries.size() ) {
            throw new NotFoundException(
                "atIndexLocation must be less than or equal to the size of the AccessControlEntry collection" );
        }

        AclEntry ace = new AclEntry( null, this, sid, permission, granting );

        int osize = this.entries.size();
        synchronized ( entries ) {
            this.entries.add( atIndexLocation, ace );
        }

        assert this.entries.size() == osize + 1;
    }

    @Override
    public boolean isEntriesInheriting() {
        return this.objectIdentity.getEntriesInheriting();
    }

    /**
     * Determines authorization. The order of the <code>permission</code> and <code>sid</code> arguments is
     * <em>extremely important</em>! The method will iterate through each of the <code>permission</code>s in the order
     * specified. For each iteration, all of the <code>sid</code>s will be considered, again in the order they are
     * presented. A search will then be performed for the first {@link AccessControlEntry} object that directly matches
     * that <code>permission:sid</code> combination. When the <em>first full match</em> is found (ie an ACE that has the
     * SID currently being searched for and the exact permission bit mask being search for), the grant or deny flag for
     * that ACE will prevail. If the ACE specifies to grant access, the method will return <code>true</code>. If the ACE
     * specifies to deny access, the loop will stop and the next <code>permission</code> iteration will be performed. If
     * each permission indicates to deny access, the first deny ACE found will be considered the reason for the failure
     * (as it was the first match found, and is therefore the one most logically requiring changes - although not
     * always). If absolutely no matching ACE was found at all for any permission, the parent ACL will be tried
     * (provided that there is a parent and {@link #isEntriesInheriting()} is <code>true</code>. The parent ACL will
     * also scan its parent and so on. If ultimately no matching ACE is found, a <code>NotFoundException</code> will be
     * thrown and the caller will need to decide how to handle the permission check. Similarly, if any of the SID
     * arguments presented to the method were not loaded by the ACL, <code>UnloadedSidException</code> will be thrown.
     *
     * @param permission         the exact permissions to scan for (order is important)
     * @param sids               the exact SIDs to scan for (order is important)
     * @param administrativeMode if <code>true</code> denotes the query is for administrative purposes and no auditing
     *                           will be undertaken
     * @return <code>true</code> if one of the permissions has been granted, <code>false</code> if one of the
     * permissions has been specifically revoked
     * @return false if an exact ACE for one of the permission bit masks and SID combination could not be
     * found
     * @throws UnloadedSidException if the passed SIDs are unknown to this ACL because the ACL was only loaded for a
     *                              subset of SIDs
     */
    @Override
    public boolean isGranted( List<Permission> permission, List<Sid> sids, boolean administrativeMode )
        throws NotFoundException, UnloadedSidException {
        Assert.notEmpty( permission, "Permissions required" );
        Assert.notEmpty( sids, "SIDs required" );

        if ( !this.isSidLoaded( sids ) ) {
            throw new UnloadedSidException( "ACL was not loaded for one or more SID" );
        }

        AccessControlEntry firstRejection = null;

        for ( Permission p : permission ) {
            for ( Sid sid : sids ) {
                assert sid instanceof AclSid;

                // Attempt to find exact match for this permission mask and SID
                boolean scanNextSid = true;

                for ( AccessControlEntry ace : entries ) {

                    assert ace instanceof AclEntry;

                    if ( ( ace.getPermission().getMask() == p.getMask() ) && ace.getSid().equals( sid ) ) {
                        // Found a matching ACE, so its authorization decision will prevail
                        if ( ace.isGranting() ) {
                            // Success
                            return true;
                        }

                        // Failure for this permission, so stop search
                        // We will see if they have a different permission
                        // (this permission is 100% rejected for this SID)
                        if ( firstRejection == null ) {
                            // Store first rejection for auditing reasons
                            firstRejection = ace;
                        }

                        scanNextSid = false; // helps break the loop

                        break; // exit aces loop
                    }
                }

                if ( !scanNextSid ) {
                    break; // exit SID for loop (now try next permission)
                }
            }
        }

        if ( firstRejection != null ) {
            // We found an ACE to reject the request at this point, as no
            // other ACEs were found that granted a different permission

            return false;
        }

        // No matches have been found so far
        if ( isEntriesInheriting() && ( parentAcl != null ) ) {
            // We have a parent, so let them try to find a matching ACE
            return parentAcl.isGranted( permission, sids, false );
        }

        // We either have no parent, or we're the uppermost parent; this can be expected.
        //        throw new NotFoundException( "Unable to locate a matching ACE for passed permissions and SIDs: " + this
        //                + "\nPermissions: " + StringUtils.join( permission, "," ) + "\nSIDs: " + StringUtils.join( sids, "," ) );
        //
        return false;
    }

    @Override
    public boolean isSidLoaded( List<Sid> sids ) {
        // // If loadedSids is null, this indicates all SIDs were loaded
        // // Also return true if the caller didn't specify a SID to find
        // if ( ( this.loadedSids == null ) || ( sids == null ) || ( sids.size() == 0 ) ) {
        // return true;
        // }
        //
        // // This ACL applies to a SID subset only. Iterate to check it applies.
        // for ( Sid sid : sids ) {
        // boolean found = false;
        //
        // for ( Sid loadedSid : loadedSids ) {
        // if ( sid.equals( loadedSid ) ) {
        // // this SID is OK
        // found = true;
        // break; // out of loadedSids for loop
        // }
        // }
        //
        // if ( !found ) {
        // return false;
        // }
        // }

        return true;
    }

    @Override
    public void setEntriesInheriting( boolean entriesInheriting ) {
        aclAuthorizationStrategy.securityCheck( this, AclAuthorizationStrategy.CHANGE_GENERAL );
        objectIdentity.setEntriesInheriting( entriesInheriting );
    }

    @Override
    public void setOwner( Sid newOwner ) {
        aclAuthorizationStrategy.securityCheck( this, AclAuthorizationStrategy.CHANGE_OWNERSHIP );
        Assert.notNull( newOwner, "Owner required" );
        this.objectIdentity.setOwnerSid( newOwner );
    }

    @Override
    public void setParent( Acl newParent ) {
        aclAuthorizationStrategy.securityCheck( this, AclAuthorizationStrategy.CHANGE_GENERAL );
        Assert.isTrue( newParent == null || !newParent.equals( this ), "Cannot be the parent of yourself: " + newParent );
        this.parentAcl = ( AclImpl ) newParent;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append( "AclImpl[" );
        sb.append( "id: " ).append( this.objectIdentity.getId() ).append( "; " );
        sb.append( "objectIdentity: " ).append( this.objectIdentity ).append( "; " );
        sb.append( "owner: " ).append( this.objectIdentity.getOwnerSid() ).append( "; " );

        int count = 0;

        for ( AccessControlEntry ace : this.entries ) {
            count++;

            if ( count == 1 ) {
                sb.append( "\r\n" );
            }

            sb.append( ace ).append( "\r\n" );
        }

        if ( count == 0 ) {
            sb.append( "no ACEs; " );
        }

        sb.append( "inheriting: " ).append( this.objectIdentity.getEntriesInheriting() ).append( "; " );
        sb.append( "parent: " ).append(
            ( this.parentAcl == null ) ? "Null" : this.parentAcl.getObjectIdentity().toString() );
        sb.append( "; " );
        sb.append( "aclAuthorizationStrategy: " ).append( this.aclAuthorizationStrategy ).append( "; " );
        // sb.append( "auditLogger: " ).append( this.auditLogger );
        sb.append( "]" );

        return sb.toString();
    }

    @Override
    public void updateAce( int aceIndex, Permission permission ) throws NotFoundException {
        aclAuthorizationStrategy.securityCheck( this, AclAuthorizationStrategy.CHANGE_GENERAL );
        verifyAceIndexExists( aceIndex );

        synchronized ( entries ) {
            AclEntry ace = entries.get( aceIndex );
            ace.setPermission( permission );
        }
    }

    private void verifyAceIndexExists( int aceIndex ) {
        if ( aceIndex < 0 ) {
            throw new NotFoundException( "aceIndex must be greater than or equal to zero" );
        }
        if ( aceIndex >= this.entries.size() ) {
            throw new NotFoundException( "aceIndex must refer to an index of the AccessControlEntry list. "
                + "List size is " + entries.size() + ", index was " + aceIndex );
        }
    }
}
