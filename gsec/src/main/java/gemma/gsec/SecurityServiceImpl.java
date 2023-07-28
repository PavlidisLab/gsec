/*
 * The Gemma project
 *
 * Copyright (c) 2007 University of British Columbia
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
package gemma.gsec;

import gemma.gsec.acl.domain.AclGrantedAuthoritySid;
import gemma.gsec.acl.domain.AclPrincipalSid;
import gemma.gsec.acl.domain.AclService;
import gemma.gsec.authentication.UserManager;
import gemma.gsec.model.Securable;
import gemma.gsec.model.UserGroup;
import gemma.gsec.util.SecurityUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * Methods for changing security on objects, creating and modifying groups, checking security on objects.
 * <p>
 * We removed the ACL filtering/checking from most of these methods, because it results in basically checking
 * permissions inside of methods that are checking permissions etc. We assume that anybody with read access on an object
 * can know something about its security state.
 *
 * @author keshav
 * @author paul
 * @version $Id: SecurityServiceImpl.java,v 1.28 2013/12/12 00:10:12 paul Exp $
 */
public class SecurityServiceImpl implements SecurityService {

    private final Log log = LogFactory.getLog( SecurityServiceImpl.class );

    private final AclService aclService;
    private final SessionRegistry sessionRegistry;
    private final ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy;
    private final SidRetrievalStrategy sidRetrievalStrategy;
    private UserManager userManager;

    public SecurityServiceImpl( AclService aclService, SessionRegistry sessionRegistry, ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy, SidRetrievalStrategy sidRetrievalStrategy ) {
        this.aclService = aclService;
        this.sessionRegistry = sessionRegistry;
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#addUserToGroup(java.lang.String, java.lang.String)
     */
    @Override
    public void addUserToGroup( String userName, String groupName ) {
        this.userManager.addUserToGroup( userName, groupName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#arePrivate(java.util.Collection)
     */
    @Override
    public <T extends Securable> Map<T, Boolean> arePrivate( Collection<T> securables ) {
        Map<T, Boolean> result = new HashMap<>();
        Map<ObjectIdentity, T> objectIdentities = getObjectIdentities( securables );

        if ( objectIdentities.isEmpty() ) return result;

        /*
         * Take advantage of fast bulk loading of ACLs. Other methods should adopt this if they turn out to be heavily
         * used/slow.
         */
        Map<ObjectIdentity, Acl> acls;
        try {
            acls = aclService.readAclsById( new Vector<>( objectIdentities.keySet() ) );
        } catch ( NotFoundException e ) {
            acls = Collections.emptyMap();
        }

        for ( ObjectIdentity oi : acls.keySet() ) {
            Acl a = acls.get( oi );
            boolean p = a != null && SecurityUtil.isPrivate( a );
            result.put( objectIdentities.get( oi ), p );
        }
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#areShared(java.util.Collection)
     */
    @Override
    public <T extends Securable> Map<T, Boolean> areShared( Collection<T> securables ) {
        Map<T, Boolean> result = new HashMap<>();
        Map<ObjectIdentity, T> objectIdentities = getObjectIdentities( securables );

        if ( objectIdentities.isEmpty() ) return result;

        Map<ObjectIdentity, Acl> acls;
        try {
            acls = aclService.readAclsById( new Vector<>( objectIdentities.keySet() ) );
        } catch ( NotFoundException e ) {
            acls = Collections.emptyMap();
        }

        for ( ObjectIdentity oi : acls.keySet() ) {
            Acl a = acls.get( oi );
            boolean p = a != null && SecurityUtil.isShared( a );
            result.put( objectIdentities.get( oi ), p );
        }
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#choosePrivate(java.util.Collection)
     */
    @Override
    public <T extends Securable> Collection<T> choosePrivate( Collection<T> securables ) {
        Collection<T> result = new HashSet<>();

        if ( securables.isEmpty() ) return result;

        Map<T, Boolean> arePrivate = arePrivate( securables );

        for ( T s : securables ) {
            if ( arePrivate.get( s ) ) result.add( s );
        }
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#choosePublic(java.util.Collection)
     */
    @Override
    public <T extends Securable> Collection<T> choosePublic( Collection<T> securables ) {
        Collection<T> result = new HashSet<>();

        if ( securables.isEmpty() ) return result;

        Map<T, Boolean> arePrivate = arePrivate( securables );

        for ( T s : securables ) {
            if ( !arePrivate.get( s ) ) result.add( s );
        }
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#createGroup(java.lang.String)
     */
    @Override
    public void createGroup( String groupName ) {

        /*
         * Nice if we can get around this uniqueness constraint...but I guess it's not easy.
         */
        if ( userManager.groupExists( groupName ) ) {
            throw new IllegalArgumentException( "A group already exists with that name: " + groupName );
        }

        /*
         * We do make the groupAuthority unique.
         */
        String groupAuthority = groupName.toUpperCase() + "_" + randomGroupNameSuffix();

        List<GrantedAuthority> auths = new ArrayList<>();
        auths.add( new SimpleGrantedAuthority( groupAuthority ) );

        this.userManager.createGroup( groupName, auths );
        addUserToGroup( userManager.getCurrentUsername(), groupName );

        // make sure all current and future members of the group will be able to see the group
        // UserGroup group = userService.findGroupByName( groupName );
        // if ( group != null ) { // really shouldn't be null
        // this should be done by the AclAdvice. We can't do it here because permissions aren't yet set up!
        // this.makeReadableByGroup( group, group.getName() );
        // } else {
        // log.error(
        // "Loading group that was just created failed. Read permissions were not granted to group, see bug 2840." );
        // }

    }

    private static final String ALLOWED_CHARS_IN_GROUP_NAME_SUFFIX = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    private String randomGroupNameSuffix() {
        Random random = new Random();
        char[] buffer = new char[32];
        for ( int i = 0; i < buffer.length; i++ ) {
            buffer[i] = ALLOWED_CHARS_IN_GROUP_NAME_SUFFIX.charAt( random.nextInt( ALLOWED_CHARS_IN_GROUP_NAME_SUFFIX.length() ) );
        }
        return new String( buffer );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#editableBy(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public Collection<String> editableBy( Securable s ) {

        Collection<String> allUsers = userManager.findAllUsers();

        Collection<String> result = new HashSet<>();

        for ( String u : allUsers ) {
            if ( isEditableByUser( s, u ) ) {
                result.add( u );
            }
        }

        return result;

    }

    private MutableAcl getAcl( Securable s ) {
        ObjectIdentity oi = objectIdentityRetrievalStrategy.getObjectIdentity( s );
        return ( MutableAcl ) aclService.readAclById( oi );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getAuthenticatedUserCount()
     */
    @Override
    public Integer getAuthenticatedUserCount() {
        return this.sessionRegistry.getAllPrincipals().size();
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getAuthenticatedUserNames()
     */
    @Override
    @Secured("GROUP_ADMIN")
    public Collection<String> getAuthenticatedUserNames() {
        List<Object> allPrincipals = this.sessionRegistry.getAllPrincipals();
        Collection<String> result = new HashSet<>();
        for ( Object o : allPrincipals ) {
            result.add( o.toString() );
        }
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getAvailableSids()
     */
    @Override
    @Secured("GROUP_ADMIN")
    public Collection<Sid> getAvailableSids() {

        Collection<Sid> results = new HashSet<>();

        Collection<String> users = userManager.findAllUsers();

        for ( String u : users ) {
            results.add( new AclPrincipalSid( u ) );
        }

        Collection<String> groups = userManager.findAllGroups();

        for ( String g : groups ) {
            List<GrantedAuthority> ga = userManager.findGroupAuthorities( g );
            for ( GrantedAuthority grantedAuthority : ga ) {
                results.add( new AclGrantedAuthoritySid( grantedAuthority.getAuthority() ) );
            }
        }

        return results;
    }

    /**
     * From the group name get the authority which should be underscored with GROUP_
     *
     * @param groupName The group name e.g. fish
     * @return The authority e.g. GROUP_FISH_...
     */
    @Override
    public String getGroupAuthorityNameFromGroupName( String groupName ) {
        Collection<String> groups = checkForGroupAccessByCurrentuser( groupName );

        if ( !groups.contains( groupName ) && !SecurityUtil.isUserAdmin() ) {
            throw new AccessDeniedException( "User doesn't have access to that group" );
        }

        List<GrantedAuthority> groupAuthorities = userManager.findGroupAuthorities( groupName );

        if ( groupAuthorities == null || groupAuthorities.isEmpty() ) {
            throw new IllegalStateException( "Group has no authorities" );
        }

        if ( groupAuthorities.size() > 1 ) {
            throw new UnsupportedOperationException( "Sorry, groups can only have a single authority" );
        }

        GrantedAuthority ga = groupAuthorities.get( 0 );
        return userManager.getRolePrefix() + ( ga.getAuthority() );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getGroupsEditableBy(java.util.Collection)
     */
    @Override
    public <T extends Securable> Map<T, Collection<String>> getGroupsEditableBy( Collection<T> securables ) {
        Collection<String> groupNames = getGroupsUserCanView();

        Map<T, Collection<String>> result = new HashMap<>();

        List<Permission> write = new ArrayList<>();
        write.add( BasePermission.WRITE );

        List<Permission> admin = new ArrayList<>();
        admin.add( BasePermission.ADMINISTRATION );

        for ( String groupName : groupNames ) {
            Map<T, Boolean> groupHasPermission = this.groupHasPermission( securables, write, groupName );

            populateGroupsEditableBy( result, groupName, groupHasPermission );

            groupHasPermission = this.groupHasPermission( securables, admin, groupName );

            populateGroupsEditableBy( result, groupName, groupHasPermission );

        }

        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getGroupsEditableBy(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public Collection<String> getGroupsEditableBy( Securable s ) {
        Collection<String> groupNames = getGroupsUserCanView();

        Collection<String> result = new HashSet<>();

        for ( String string : groupNames ) {
            if ( this.isEditableByGroup( s, string ) ) {
                result.add( string );
            }
        }

        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getGroupsReadableBy(java.util.Collection)
     */
    @Override
    public <T extends Securable> Map<T, Collection<String>> getGroupsReadableBy( Collection<T> securables ) {

        Map<T, Collection<String>> result = new HashMap<>();

        if ( securables.isEmpty() ) return result;

        Collection<String> groupNames = getGroupsUserCanView();

        List<Permission> read = new ArrayList<>();
        read.add( BasePermission.READ );

        List<Permission> admin = new ArrayList<>();
        admin.add( BasePermission.ADMINISTRATION );

        for ( String groupName : groupNames ) {
            Map<T, Boolean> groupHasPermission = this.groupHasPermission( securables, read, groupName );

            populateGroupsEditableBy( result, groupName, groupHasPermission );

            groupHasPermission = this.groupHasPermission( securables, admin, groupName );

            populateGroupsEditableBy( result, groupName, groupHasPermission );
        }

        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getGroupsReadableBy(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public Collection<String> getGroupsReadableBy( Securable s ) {
        Collection<String> groupNames = getGroupsUserCanView();

        Collection<String> result = new HashSet<>();

        for ( String string : groupNames ) {
            if ( this.isReadableByGroup( s, string ) ) {
                result.add( string );
            }
        }

        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getGroupsUserCanEdit(java.lang.String)
     */
    @Override
    public Collection<String> getGroupsUserCanEdit( String userName ) {
        Collection<String> groupNames = getGroupsUserCanView();

        Collection<String> result = new HashSet<>();
        for ( String gname : groupNames ) {
            UserGroup g = userManager.findGroupByName( gname );
            if ( this.isEditableByUser( g, userName ) ) {
                result.add( gname );
            }
        }

        return result;

    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getOwner(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public Sid getOwner( Securable s ) {
        ObjectIdentity oi = this.objectIdentityRetrievalStrategy.getObjectIdentity( s );
        Acl a = this.aclService.readAclById( oi );
        return a.getOwner();
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#getOwners(java.util.Collection)
     */
    @Override
    public <T extends Securable> Map<T, Sid> getOwners( Collection<T> securables ) {
        Map<T, Sid> result = new HashMap<>();
        Map<ObjectIdentity, T> objectIdentities = getObjectIdentities( securables );

        if ( securables.isEmpty() ) return result;

        /*
         * Take advantage of fast bulk loading of ACLs. Other methods sohuld adopt this if they turn out to be heavily
         * used/slow.
         */
        Map<ObjectIdentity, Acl> acls;
        try {
            acls = aclService.readAclsById( new Vector<>( objectIdentities.keySet() ) );
        } catch ( NotFoundException e ) {
            acls = Collections.emptyMap();
        }

        for ( ObjectIdentity oi : acls.keySet() ) {
            Acl a = acls.get( oi );
            if ( a != null ) {
                Sid owner = a.getOwner();
                result.put( objectIdentities.get( oi ), owner );
            }
        }
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isEditable(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public boolean isEditable( Securable s ) {

        if ( !SecurityUtil.isUserLoggedIn() ) {
            return false;
        }

        String currentUser = this.userManager.getCurrentUsername();

        List<Permission> requiredPermissions = new ArrayList<>();

        requiredPermissions.add( BasePermission.WRITE );
        if ( hasPermission( s, requiredPermissions, currentUser ) ) {
            return true;
        }

        requiredPermissions.clear();
        requiredPermissions.add( BasePermission.ADMINISTRATION );
        return hasPermission( s, requiredPermissions, currentUser );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isEditableByGroup(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    public boolean isEditableByGroup( Securable s, String groupName ) {
        List<Permission> requiredPermissions = new ArrayList<>();
        requiredPermissions.add( BasePermission.WRITE );

        if ( groupHasPermission( s, requiredPermissions, groupName ) ) {
            return true;
        }

        requiredPermissions.clear();
        requiredPermissions.add( BasePermission.ADMINISTRATION );
        return groupHasPermission( s, requiredPermissions, groupName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isEditableByUser(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    public boolean isEditableByUser( Securable s, String userName ) {
        List<Permission> requiredPermissions = new ArrayList<>();
        requiredPermissions.add( BasePermission.WRITE );
        if ( hasPermission( s, requiredPermissions, userName ) ) {
            return true;
        }

        requiredPermissions.clear();
        requiredPermissions.add( BasePermission.ADMINISTRATION );
        return hasPermission( s, requiredPermissions, userName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isOwnedByCurrentUser(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public boolean isOwnedByCurrentUser( Securable s ) {
        ObjectIdentity oi = objectIdentityRetrievalStrategy.getObjectIdentity( s );

        try {
            Acl acl = this.aclService.readAclById( oi );

            Sid owner = acl.getOwner();
            if ( owner == null ) return false;

            /*
             * Special case: if we're the administrator, and the owner of the data is GROUP_ADMIN, we are considered the
             * owner.
             */
            if ( owner instanceof AclGrantedAuthoritySid
                && SecurityUtil.isUserAdmin()
                && ( ( AclGrantedAuthoritySid ) owner ).getGrantedAuthority().equals(
                AuthorityConstants.ADMIN_GROUP_AUTHORITY ) ) {
                return true;
            }

            if ( owner instanceof AclPrincipalSid ) {
                String ownerName = ( ( AclPrincipalSid ) owner ).getPrincipal();

                if ( ownerName.equals( userManager.getCurrentUsername() ) ) {
                    return true;
                }

                /*
                 * Special case: if the owner is an administrator, and we're an administrator, we are considered the
                 * owner. Note that the intention is that usually the owner would be a GrantedAuthority (see last case,
                 * below), not a Principal, but this hasn't always been instituted.
                 */
                if ( SecurityUtil.isUserAdmin() ) {
                    try {
                        Collection<? extends GrantedAuthority> authorities = userManager.loadUserByUsername( ownerName )
                            .getAuthorities();
                        for ( GrantedAuthority grantedAuthority : authorities ) {
                            if ( grantedAuthority.getAuthority().equals( AuthorityConstants.ADMIN_GROUP_AUTHORITY ) ) {
                                return true;
                            }
                        }
                    } catch ( UsernameNotFoundException e ) {
                        log.warn( "Owner " + ownerName + " could not be retrieved to check role: " + e.getMessage() );
                        return false;
                    }

                    return false;
                }

            }

            return false;

        } catch ( NotFoundException nfe ) {
            return false;
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isPrivate(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public boolean isPrivate( Securable s ) {

        if ( s == null ) {
            log.warn( "Null object: considered public!" );
            return false;
        }

        /*
         * Implementation note: this code mimics AclEntryVoter.vote, but in adminsitrative mode so no auditing etc
         * happens.
         */

        Sid anonSid = new AclGrantedAuthoritySid( new SimpleGrantedAuthority(
            AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY ) );

        List<Sid> sids = new Vector<>();
        sids.add( anonSid );

        ObjectIdentity oi = objectIdentityRetrievalStrategy.getObjectIdentity( s );

        /*
         * Note: in theory, it should pay attention to the sid we ask for and return nothing if there is no acl.
         * However, the implementation actually ignores the sid argument.
         */
        try {
            Acl acl = this.aclService.readAclById( oi, sids );

            assert acl != null;

            return SecurityUtil.isPrivate( acl );
        } catch ( NotFoundException nfe ) {
            return true;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isPublic(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public boolean isPublic( Securable s ) {
        return !isPrivate( s );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isReadableByGroup(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    public boolean isReadableByGroup( Securable s, String groupName ) {
        List<Permission> requiredPermissions = new ArrayList<>();
        requiredPermissions.add( BasePermission.READ );

        if ( groupHasPermission( s, requiredPermissions, groupName ) ) {
            return true;
        }

        requiredPermissions.clear();
        requiredPermissions.add( BasePermission.ADMINISTRATION );
        return groupHasPermission( s, requiredPermissions, groupName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isShared(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    public boolean isShared( Securable s ) {
        if ( s == null ) {
            return false;
        }

        /*
         * Implementation note: this code mimics AclEntryVoter.vote, but in adminsitrative mode so no auditing etc
         * happens.
         */

        ObjectIdentity oi = objectIdentityRetrievalStrategy.getObjectIdentity( s );

        /*
         * Note: in theory, it should pay attention to the sid we ask for and return nothing if there is no acl.
         * However, the implementation actually ignores the sid argument. See BasicLookupStrategy
         */
        try {
            Acl acl = this.aclService.readAclById( oi );

            return SecurityUtil.isShared( acl );
        } catch ( NotFoundException nfe ) {
            return true;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#isViewableByUser(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    public boolean isViewableByUser( Securable s, String userName ) {
        List<Permission> requiredPermissions = new ArrayList<>();
        requiredPermissions.add( BasePermission.READ );
        if ( hasPermission( s, requiredPermissions, userName ) ) {
            return true;
        }

        requiredPermissions.clear();
        requiredPermissions.add( BasePermission.ADMINISTRATION );
        return hasPermission( s, requiredPermissions, userName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makeOwnedByUser(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    @Secured("GROUP_ADMIN")
    public void makeOwnedByUser( Securable s, String userName ) {
        MutableAcl acl = getAcl( s );

        Sid owner = acl.getOwner();
        if ( owner instanceof AclPrincipalSid && ( ( AclPrincipalSid ) owner ).getPrincipal().equals( userName ) ) {
            /*
             * Already owned by the given user -- note we don't check if the user exists here.
             */
            return;
        }

        // make sure user exists and is enabled.
        UserDetails user = this.userManager.loadUserByUsername( userName );
        if ( !user.isEnabled() || !user.isAccountNonExpired() || !user.isAccountNonLocked() ) {
            throw new IllegalArgumentException( "User  " + userName + " has a disabled account" );
        }

        acl.setOwner( new AclPrincipalSid( userName ) );
        aclService.updateAcl( acl );

        /*
         * FIXME: I don't know if these are necessary if you are the owner.
         */
        addPrincipalAuthority( s, BasePermission.WRITE, userName );
        addPrincipalAuthority( s, BasePermission.READ, userName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makePrivate(java.util.Collection)
     */
    @Override
    public void makePrivate( Collection<? extends Securable> objs ) {
        for ( Securable s : objs ) {
            makePrivate( s );
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makePrivate(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public void makePrivate( Securable object ) {
        if ( object == null ) {
            return;
        }

        if ( isPrivate( object ) ) {
            log.warn( "Object is already private: " + object );
            return;
        }

        /*
         * Remove ACE for IS_AUTHENTICATED_ANOYMOUSLY, if it's there.
         */
        String authorityToRemove = AuthorityConstants.IS_AUTHENTICATED_ANONYMOUSLY;

        removeGrantedAuthority( object, BasePermission.READ, authorityToRemove );

        // will fail until flush...
        // if ( isPublic( object ) ) {
        //     throw new IllegalStateException( "Failed to make object private: " + object );
        // }

    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makePublic(java.util.Collection)
     */
    @Override
    public void makePublic( Collection<? extends Securable> objs ) {
        for ( Securable s : objs ) {
            makePublic( s );
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makePublic(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public void makePublic( Securable object ) {

        if ( object == null ) {
            return;
        }

        if ( isPublic( object ) ) {
            log.warn( "Object is already public" );
            return;
        }

        /*
         * Add an ACE for IS_AUTHENTICATED_ANOYMOUSLY.
         */

        MutableAcl acl = getAcl( object );

        acl.insertAce( acl.getEntries().size(), BasePermission.READ, new AclGrantedAuthoritySid(
            new SimpleGrantedAuthority( AuthorityConstants.IS_AUTHENTICATED_ANONYMOUSLY ) ), true );

        aclService.updateAcl( acl );

        // this will fail if the acl changes haven't been flushed ...
        // if ( isPrivate( object ) ) {
        //     throw new IllegalStateException( "Failed to make object public: " + object );
        // }

    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makeReadableByGroup(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public void makeReadableByGroup( Securable s, String groupName ) throws AccessDeniedException {

        if ( StringUtils.isEmpty( groupName.trim() ) ) {
            throw new IllegalArgumentException( "'group' cannot be null" );
        }

        Collection<String> groups = checkForGroupAccessByCurrentuser( groupName );

        if ( !groups.contains( groupName ) && !SecurityUtil.isUserAdmin() ) {
            throw new AccessDeniedException( "User doesn't have access to that group" );
        }

        if ( isReadableByGroup( s, groupName ) ) {
            return;
        }

        addGroupAuthority( s, BasePermission.READ, groupName );

    }

    /*
     * (non-Javadoc)
     *
     * @see
     * ubic.gemma.security.SecurityService#makeUnreadableByGroup(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public void makeUnreadableByGroup( Securable s, String groupName ) throws AccessDeniedException {

        if ( StringUtils.isEmpty( groupName.trim() ) ) {
            throw new IllegalArgumentException( "'group' cannot be null" );
        }

        removeGrantedAuthority( s, BasePermission.READ, getGroupAuthorityNameFromGroupName( groupName ) );
        removeGrantedAuthority( s, BasePermission.WRITE, getGroupAuthorityNameFromGroupName( groupName ) );
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * ubic.gemma.security.SecurityService#makeUnwriteableByGroup(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public void makeUnwriteableByGroup( Securable s, String groupName ) throws AccessDeniedException {

        if ( StringUtils.isEmpty( groupName.trim() ) ) {
            throw new IllegalArgumentException( "'group' cannot be null" );
        }

        removeGrantedAuthority( s, BasePermission.WRITE, getGroupAuthorityNameFromGroupName( groupName ) );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#makeWriteableByGroup(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public void makeWriteableByGroup( Securable s, String groupName ) throws AccessDeniedException {

        if ( StringUtils.isEmpty( groupName.trim() ) ) {
            throw new IllegalArgumentException( "'group' cannot be null" );
        }

        Collection<String> groups = checkForGroupAccessByCurrentuser( groupName );

        if ( !groups.contains( groupName ) && !SecurityUtil.isUserAdmin() ) {
            throw new AccessDeniedException( "User doesn't have access to that group" );
        }

        if ( isEditableByGroup( s, groupName ) ) {
            return;
        }
        // Bug 1835: Duplicate ACLS were added to an object for group read access as part of writable
        // only add read access if not there already.

        if ( !( isReadableByGroup( s, groupName ) ) ) {
            addGroupAuthority( s, BasePermission.READ, groupName );
        }
        addGroupAuthority( s, BasePermission.WRITE, groupName );

    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#readableBy(ubic.gemma.model.common.auditAndSecurity.Securable)
     */
    @Override
    @Secured("ACL_SECURABLE_EDIT")
    public Collection<String> readableBy( Securable s ) {
        Collection<String> allUsers = userManager.findAllUsers();

        Collection<String> result = new HashSet<>();

        for ( String u : allUsers ) {
            if ( isViewableByUser( s, u ) ) {
                result.add( u );
            }
        }

        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#removeUserFromGroup(java.lang.String, java.lang.String)
     */
    @Override
    public void removeUserFromGroup( String userName, String groupName ) {
        this.userManager.removeUserFromGroup( userName, groupName );
    }

    /*
     * (non-Javadoc)
     *
     * @see ubic.gemma.security.SecurityService#setOwner(ubic.gemma.model.common.auditAndSecurity.Securable,
     * java.lang.String)
     */
    @Override
    @Secured("GROUP_ADMIN")
    public void setOwner( Securable s, String userName ) {

        // make sure user exists and is enabled.
        UserDetails user = this.userManager.loadUserByUsername( userName );
        if ( !user.isEnabled() || !user.isAccountNonExpired() || !user.isAccountNonLocked() ) {
            throw new IllegalArgumentException( "User  " + userName + " has a disabled account" );
        }

        ObjectIdentity oi = this.objectIdentityRetrievalStrategy.getObjectIdentity( s );
        MutableAcl a = ( MutableAcl ) this.aclService.readAclById( oi );

        a.setOwner( new AclPrincipalSid( userName ) );

        this.aclService.updateAcl( a );

    }

    /**
     * Provide permission to the given group on the given securable.
     *
     * @param groupName e.g. "GROUP_JOESLAB"
     */
    private void addGroupAuthority( Securable s, Permission permission, String groupName ) {
        MutableAcl acl = getAcl( s );

        List<GrantedAuthority> groupAuthorities = userManager.findGroupAuthorities( groupName );

        if ( groupAuthorities == null || groupAuthorities.isEmpty() ) {
            throw new IllegalStateException( "Group has no authorities" );
        }

        if ( groupAuthorities.size() > 1 ) {
            throw new UnsupportedOperationException( "Sorry, groups can only have a single authority" );
        }

        GrantedAuthority ga = groupAuthorities.get( 0 );

        acl.insertAce( acl.getEntries().size(), permission, new AclGrantedAuthoritySid( userManager.getRolePrefix()
            + ga ), true );
        aclService.updateAcl( acl );
    }

    /**
     * @param principal i.e. username
     */
    private void addPrincipalAuthority( Securable s, Permission permission, String principal ) {
        MutableAcl acl = getAcl( s );
        acl.insertAce( acl.getEntries().size(), permission, new AclPrincipalSid( principal ), true );
        aclService.updateAcl( acl );
    }

    /**
     * Check if the current user can access the given group.
     */
    private Collection<String> checkForGroupAccessByCurrentuser( String groupName ) {
        if ( groupName.equals( AuthorityConstants.ADMIN_GROUP_NAME ) ) {
            throw new AccessDeniedException( "Attempt to mess with ADMIN privileges denied" );
        }
        return userManager.findGroupsForUser( userManager.getCurrentUsername() );
    }

    /**
     * @return groups that the current user can view. For administrators, this is all groups.
     */
    private Collection<String> getGroupsUserCanView() {
        Collection<String> groupNames;
        try {
            // administrator...
            groupNames = userManager.findAllGroups();
        } catch ( AccessDeniedException e ) {
            // I'm not sure this actually happens. Usermanager.findAllGroups should just show all of the user's viewable
            // groups.
            groupNames = userManager.findGroupsForUser( userManager.getCurrentUsername() );
        }
        return groupNames;
    }

    private <T extends Securable> Map<ObjectIdentity, T> getObjectIdentities( Collection<T> securables ) {
        Map<ObjectIdentity, T> result = new HashMap<>();
        for ( T s : securables ) {
            result.put( objectIdentityRetrievalStrategy.getObjectIdentity( s ), s );
        }
        return result;
    }

    private <T extends Securable> Map<T, Boolean> groupHasPermission( Collection<T> securables,
        List<Permission> requiredPermissions, String groupName ) {
        Map<T, Boolean> result = new HashMap<>();
        Map<ObjectIdentity, T> objectIdentities = getObjectIdentities( securables );

        List<GrantedAuthority> auths = userManager.findGroupAuthorities( groupName );

        List<Sid> sids = new ArrayList<>();
        for ( GrantedAuthority a : auths ) {
            AclGrantedAuthoritySid sid = new AclGrantedAuthoritySid( new SimpleGrantedAuthority(
                userManager.getRolePrefix() + a.getAuthority() ) );
            sids.add( sid );
        }

        Map<ObjectIdentity, Acl> acls;
        try {
            acls = aclService.readAclsById( new Vector<>( objectIdentities.keySet() ) );
        } catch ( NotFoundException e ) {
            acls = Collections.emptyMap();
        }

        for ( ObjectIdentity oi : acls.keySet() ) {
            Acl a = acls.get( oi );
            try {
                result.put( objectIdentities.get( oi ), a != null && a.isGranted( requiredPermissions, sids, true ) );
            } catch ( NotFoundException ignore ) {
            }
        }
        return result;
    }

    private boolean groupHasPermission( Securable domainObject, List<Permission> requiredPermissions, String groupName ) {
        ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity( domainObject );

        List<GrantedAuthority> auths = userManager.findGroupAuthorities( groupName );

        List<Sid> sids = new ArrayList<>();
        for ( GrantedAuthority a : auths ) {
            AclGrantedAuthoritySid sid = new AclGrantedAuthoritySid( new SimpleGrantedAuthority(
                userManager.getRolePrefix() + a.getAuthority() ) );
            sids.add( sid );
        }

        try {
            // Lookup only ACLs for SIDs we're interested in (this actually get them all)
            Acl acl = aclService.readAclById( objectIdentity, sids );
            // administrative mode = true
            return acl.isGranted( requiredPermissions, sids, true );
        } catch ( NotFoundException ignore ) {
            return false;
        }

    }

    /*
     * Private method that really doesn't work unless you are admin
     */
    private boolean hasPermission( Securable domainObject, List<Permission> requiredPermissions, String userName ) {

        // Obtain the OID applicable to the domain object
        ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity( domainObject );

        // Obtain the SIDs applicable to the principal
        UserDetails user = userManager.loadUserByUsername( userName );
        Authentication authentication = new UsernamePasswordAuthenticationToken( userName, user.getPassword(),
            user.getAuthorities() );
        List<Sid> sids = sidRetrievalStrategy.getSids( authentication );

        Acl acl;

        try {
            acl = aclService.readAclById( objectIdentity, sids );
            // administrative mode = true
            return acl.isGranted( requiredPermissions, sids, true );
        } catch ( NotFoundException ignore ) {
            return false;
        }
    }

    private <T extends Securable> void populateGroupsEditableBy( Map<T, Collection<String>> result, String groupName,
        Map<T, Boolean> groupHasPermission ) {
        for ( T s : groupHasPermission.keySet() ) {
            if ( groupHasPermission.get( s ) ) {
                if ( !result.containsKey( s ) ) {
                    result.put( s, new HashSet<String>() );
                }
                result.get( s ).add( groupName );
            }

        }
    }

    /**
     * Wrapper method that calls removeOneGrantedAuthority to ensure that only one ace at a time is updated. A bit
     * clunky but it ensures that the code is called as a complete unit, that is an update is performed and the array
     * retrieved again after update. The reason is that we remove them by the entry index, which changes ... so we have
     * to do it "iteratively".
     *
     * @param object     The object to remove the permissions from
     * @param permission Permission to change.
     * @param authority  e.g. "GROUP_JOESLAB"
     */
    private void removeGrantedAuthority( Securable object, Permission permission, String authority ) {
        int numberOfAclsToRemove = 1;
        // for 0 or 1 acls should only call once
        while ( numberOfAclsToRemove > 0 ) {
            numberOfAclsToRemove = removeOneGrantedAuthority( object, permission, authority );
        }
    }

    /**
     * Method removes just one ace and then informs calling method the number of aces to remove
     *
     * @param object     The object to remove the permissions from
     * @param permission The permission to remove
     * @param authority  e.g. "GROUP_JOESLAB"
     * @return Number of ace records that need removing
     */
    private int removeOneGrantedAuthority( Securable object, Permission permission, String authority ) {
        int numberAclsToRemove = 0;

        MutableAcl acl = getAcl( object );

        List<Integer> toremove = new Vector<>();
        for ( int i = 0; i < acl.getEntries().size(); i++ ) {
            AccessControlEntry entry = acl.getEntries().get( i );

            if ( !entry.getPermission().equals( permission ) ) {
                continue;
            }

            Sid sid = entry.getSid();
            if ( sid instanceof AclGrantedAuthoritySid
                && ( ( AclGrantedAuthoritySid ) sid ).getGrantedAuthority().equals( authority ) ) {
                log.info( "Removing: " + permission + " from " + object + " granted to " + sid );
                toremove.add( i );
            } else {
                log.debug( "Keeping: " + permission + " on " + object + " granted to " + sid );
            }
        }

        if ( toremove.isEmpty() ) {
            // this can happen commonly, no big deal.
            if ( log.isDebugEnabled() ) log.debug( "No changes, didn't remove: " + authority );
        } else {
            numberAclsToRemove = toremove.size() - 1;
            // take the first acl
            acl.deleteAce( toremove.get( 0 ) );
            aclService.updateAcl( acl );
        }

        return numberAclsToRemove;

    }

    public void setUserManager( UserManager userManager ) {
        this.userManager = userManager;
    }
}