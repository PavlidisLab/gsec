/*
 * The Gemma project.
 * 
 * Copyright (c) 2006 University of British Columbia
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
package gemma.gsec.mda;

import gemma.gsec.AuthorityConstants;
import gemma.gsec.model.GroupAuthority;
import gemma.gsec.model.User;
import gemma.gsec.model.UserGroup;
import gemma.gsec.model.UserGroupImpl;

import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * @see UserGroup
 */
@Repository
public class UserGroupDaoImpl extends UserGroupDaoBase {

    protected final Log log = LogFactory.getLog( getClass() );

    /**
     * @param sessionFactory
     */
    @Autowired
    public UserGroupDaoImpl( SessionFactory sessionFactory ) {
        super.setSessionFactory( sessionFactory );
    }

    /*
     * (non-Javadoc)
     * 
     * @see UserGroupDao#addAuthority(UserGroup , java.lang.String)
     */
    @Override
    public void addAuthority( UserGroup group, String authority ) {

        for ( GroupAuthority ga : group.getAuthorities() ) {
            if ( ga.getAuthority().equals( authority ) ) {
                log.warn( "Group already has authority " + authority );
                return;
            }
        }

        GroupAuthority ga = GroupAuthority.Factory.newInstance();
        ga.setAuthority( authority );

        group.getAuthorities().add( ga );

        this.getHibernateTemplate().update( group );

    }

    /*
     * (non-Javadoc)
     * 
     * @see UserGroupDao#addToGroup(UserGroup , User)
     */
    @Override
    public void addToGroup( UserGroup group, User user ) {
        group.getGroupMembers().add( user );
        this.getHibernateTemplate().update( group );
    }

    /**
     * @see UserGroupDao#create(int transform, UserGroup)
     */
    @Override
    public UserGroup create( final UserGroup userGroup ) {
        if ( userGroup == null ) {
            throw new IllegalArgumentException( "UserGroup.create - 'userGroup' can not be null" );
        }
        if ( userGroup.getName().equals( AuthorityConstants.USER_GROUP_NAME )
                || userGroup.getName().equals( AuthorityConstants.ADMIN_GROUP_NAME )
                || userGroup.getName().equals( AuthorityConstants.AGENT_GROUP_NAME ) ) {
            throw new IllegalArgumentException( "Cannot create group with that name: " + userGroup.getName() );
        }
        this.getHibernateTemplate().save( userGroup );
        return userGroup;
    }

    /*
     * (non-Javadoc)
     * 
     * @see UserGroupDao#findGroupsForUser(ubic.gemma.model.common.auditAndSecurity .User)
     */
    @Override
    public Collection<UserGroup> findGroupsForUser( User user ) {
        return this.getHibernateTemplate().findByNamedParam(
                "select ug from UserGroupImpl ug inner join ug.groupMembers memb where memb = :user", "user", user );
    }

    @Override
    public void remove( Long id ) {
        if ( id == null ) {
            throw new IllegalArgumentException( "UserGroup.remove - 'id' can not be null" );
        }
        UserGroup userGroup = this.load( id );
        if ( userGroup == null ) {
            throw new IllegalArgumentException( "UserGroup.remove - 'userGroup' can not be null" );
        }
        // this check is done higher up as well...
        if ( userGroup.getName().equals( AuthorityConstants.USER_GROUP_NAME )
                || userGroup.getName().equals( AuthorityConstants.ADMIN_GROUP_NAME )
                || userGroup.getName().equals( AuthorityConstants.AGENT_GROUP_NAME ) ) {
            throw new IllegalArgumentException( "Cannot delete group: " + userGroup );
        }

        this.getSessionFactory().getCurrentSession().delete( userGroup );
    }

    /**
     * @see UserGroupDao#remove(UserGroup)
     */
    @Override
    public void remove( UserGroup userGroup ) {
        if ( userGroup == null ) {
            throw new IllegalArgumentException( "UserGroup.remove - 'userGroup' can not be null" );
        }
        this.remove( userGroup.getId() );
    }

    /*
     * (non-Javadoc)
     * 
     * @see UserGroupDao#removeAuthority(ubic.gemma.model.common.auditAndSecurity .UserGroup, java.lang.String)
     */
    @Override
    public void removeAuthority( UserGroup group, String authority ) {

        for ( Iterator<GroupAuthority> iterator = group.getAuthorities().iterator(); iterator.hasNext(); ) {
            GroupAuthority ga = iterator.next();
            if ( ga.getAuthority().equals( authority ) ) {
                iterator.remove();
            }
        }

        this.getHibernateTemplate().update( group );
    }

    /**
     * @see UserGroupDao#update(UserGroup)
     */
    @Override
    public void update( UserGroup userGroup ) {
        if ( userGroup == null ) {
            throw new IllegalArgumentException( "UserGroup.update - 'userGroup' can not be null" );
        }

        UserGroup groupToUpdate = this.getHibernateTemplate().load( UserGroupImpl.class, userGroup.getId() );

        String name = groupToUpdate.getName();
        if ( !name.equals( userGroup.getName() )
                && ( name.equals( AuthorityConstants.USER_GROUP_NAME )
                        || name.equals( AuthorityConstants.ADMIN_GROUP_NAME ) || name
                            .equals( AuthorityConstants.AGENT_GROUP_NAME ) ) ) {
            throw new IllegalArgumentException( "Cannot change name of group: " + groupToUpdate.getName() );
        }

        this.getHibernateTemplate().update( userGroup );
    }
}