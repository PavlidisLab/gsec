/*
 * The Gemma project
 * 
 * Copyright (c) 2011 University of British Columbia
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
package gemma.gsec.authentication;

import gemma.gsec.AuthorityConstants;
import gemma.gsec.SecurityService;
import gemma.gsec.acl.domain.AclGrantedAuthoritySid;
import gemma.gsec.acl.domain.AclService;
import gemma.gsec.mda.UserDao;
import gemma.gsec.mda.UserGroupDao;
import gemma.gsec.model.GroupAuthority;
import gemma.gsec.model.User;
import gemma.gsec.model.UserExistsException;
import gemma.gsec.model.UserGroup;
import gemma.gsec.util.SecurityUtil;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @see ubic.gemma.security.authentication.UserService
 * @author pavlidis
 * @version $Id: UserServiceImpl.java,v 1.10 2013/09/21 01:28:45 paul Exp $
 */
@Service
@Transactional
public class UserServiceImpl implements UserService {

    @Autowired
    UserDao userDao;

    @Autowired
    UserGroupDao userGroupDao;

    @Autowired
    private AclService aclService;

    @Autowired
    private SecurityService securityService;

    @Override
    public void addGroupAuthority( UserGroup group, String authority ) {
        this.userGroupDao.addAuthority( group, authority );
    }

    @Override
    public void addUserToGroup( UserGroup group, User user ) {
        // add user to list of members
        group.getGroupMembers().add( user );
        this.userGroupDao.update( group );

        // FIXME: Maybe user registration should be a completely separate, isolated code path.
        // Or maybe call to makeReadableByGroup shouldn't be here in the first place.
        // if (group.getName().equals( "Users" )) {
        // USERS group is a special case
        // } else {
        // grant read permissions to newly added user
        // this.securityService.makeReadableByGroup( group, group.getName() );
        // }
    }

    @Override
    public User create( final User user ) throws UserExistsException {

        if ( user.getUserName() == null ) {
            throw new IllegalArgumentException( "UserName cannot be null" );
        }

        if ( this.userDao.findByUserName( user.getUserName() ) != null ) {
            throw new UserExistsException( "User '" + user.getUserName() + "' already exists!" );
        }

        if ( this.findByEmail( user.getEmail() ) != null ) {
            throw new UserExistsException( "A user with email address '" + user.getEmail() + "' already exists." );
        }

        try {
            return this.userDao.create( user );
        } catch ( DataIntegrityViolationException e ) {
            throw new UserExistsException( "User '" + user.getUserName() + "' already exists!" );
        } catch ( InvalidDataAccessResourceUsageException e ) {
            // shouldn't happen if we don't have duplicates in the first place...but just in case.
            throw new UserExistsException( "User '" + user.getUserName() + "' already exists!" );
        }

    }

    @Override
    public UserGroup create( UserGroup group ) {
        return this.userGroupDao.create( group );
    }

    @Override
    public void delete( User user ) {
        for ( UserGroup group : this.userDao.loadGroups( user ) ) {
            group.getGroupMembers().remove( user );
            this.userGroupDao.update( group );
        }

        this.userDao.remove( user );
    }

    @Override
    public void delete( UserGroup group ) {
        String groupName = group.getName();

        if ( !groupExists( groupName ) ) {
            throw new IllegalArgumentException( "No group with that name: " + groupName );
        }

        /*
         * make sure this isn't one of the special groups
         */
        if ( groupName.equals( AuthorityConstants.USER_GROUP_NAME )
                || groupName.equals( AuthorityConstants.ADMIN_GROUP_NAME )
                || groupName.equals( AuthorityConstants.AGENT_GROUP_NAME ) ) {
            throw new IllegalArgumentException( "Cannot delete that group, it is required for system operation." );
        }

        if ( !securityService.isOwnedByCurrentUser( findGroupByName( groupName ) ) && !SecurityUtil.isUserAdmin() ) {
            throw new AccessDeniedException( "Only administrator or owner of a group can delete it" );
        }

        String authority = securityService.getGroupAuthorityNameFromGroupName( groupName );

        this.userGroupDao.remove( group );

        /*
         * clean up acls that use this group...do that last!
         */
        try {
            aclService.deleteSid( new AclGrantedAuthoritySid( authority ) );
        } catch ( DataIntegrityViolationException div ) {
            throw div;
        }
    }

    @Override
    public User findByEmail( final String email ) {
        return this.userDao.findByEmail( email );

    }

    @Override
    public User findByUserName( final String userName ) {
        return this.userDao.findByUserName( userName );
    }

    @Override
    public UserGroup findGroupByName( String name ) {
        return this.userGroupDao.findByUserGroupName( name );
    }

    @Override
    public Collection<UserGroup> findGroupsForUser( User user ) {
        return this.userGroupDao.findGroupsForUser( user );
    }

    @Override
    public boolean groupExists( String name ) {
        return this.userGroupDao.findByUserGroupName( name ) != null;
    }

    @Override
    public Collection<UserGroup> listAvailableGroups() {
        return ( Collection<UserGroup> ) this.userGroupDao.loadAll();
    }

    @Override
    public User load( final Long id ) {
        return this.userDao.load( id );
    }

    @Override
    public Collection<User> loadAll() {
        return ( Collection<User> ) this.userDao.loadAll();
    }

    @Override
    public Collection<GroupAuthority> loadGroupAuthorities( User user ) {
        return this.userDao.loadGroupAuthorities( user );
    }

    @Override
    public void removeGroupAuthority( UserGroup group, String authority ) {
        this.userGroupDao.removeAuthority( group, authority );
    }

    @Override
    public void removeUserFromGroup( User user, UserGroup group ) {
        group.getGroupMembers().remove( user );

        String userName = user.getName();
        String groupName = group.getName();

        if ( AuthorityConstants.REQUIRED_ADMINISTRATOR_USER_NAME.equals( userName )
                && AuthorityConstants.ADMIN_GROUP_NAME.equals( groupName ) ) {
            throw new IllegalArgumentException( "You cannot remove the administrator from the ADMIN group!" );
        }

        if ( AuthorityConstants.USER_GROUP_NAME.equals( groupName ) ) {
            throw new IllegalArgumentException( "You cannot remove users from the USER group!" );
        }
        this.userGroupDao.update( group );

        /*
         * TODO: if the group is empty, should we delete it? Not if it is GROUP_USER or ADMIN, but perhaps otherwise.
         */
    }

    @Override
    public void update( final User user ) {
        this.userDao.update( user );
    }

    @Override
    public void update( UserGroup group ) {
        this.userGroupDao.update( group );
    }

}
