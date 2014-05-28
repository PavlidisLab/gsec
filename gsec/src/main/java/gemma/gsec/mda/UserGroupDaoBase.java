/*
 * The Gemma project.
 * 
 * Copyright (c) 2006-2007 University of British Columbia
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

import gemma.gsec.model.UserGroup;
import gemma.gsec.model.UserGroupImpl;

import java.util.Collection;

import org.springframework.orm.hibernate3.support.HibernateDaoSupport;

/**
 * <p>
 * Base Spring DAO Class: is able to create, update, remove, load, and find objects of type <code>UserGroup</code>.
 * </p>
 * 
 * @see UserGroup
 */
public abstract class UserGroupDaoBase extends HibernateDaoSupport implements UserGroupDao {

    /**
     * @see UserGroupDao#create(int, java.util.Collection)
     */
    @Override
    public java.util.Collection<? extends UserGroup> create( final java.util.Collection<? extends UserGroup> entities ) {
        if ( entities == null ) {
            throw new IllegalArgumentException( "UserGroup.create - 'entities' can not be null" );
        }
        this.getHibernateTemplate().executeWithNativeSession(
                new org.springframework.orm.hibernate3.HibernateCallback<UserGroup>() {
                    @Override
                    public UserGroup doInHibernate( org.hibernate.Session session )
                            throws org.hibernate.HibernateException {
                        for ( java.util.Iterator<? extends UserGroup> entityIterator = entities.iterator(); entityIterator
                                .hasNext(); ) {
                            create( entityIterator.next() );
                        }
                        return null;
                    }
                } );
        return entities;
    }

    /**
     * @see UserGroupDao#findByUserGroupName(int, java.lang.String)
     */
    @Override
    public UserGroup findByUserGroupName( final java.lang.String name ) {
        return this.findByUserGroupName( "from UserGroup as userGroup where userGroup.name = :name", name );
    }

    /**
     * @see UserGroupDao#findByUserGroupName(int, java.lang.String, java.lang.String)
     */

    public UserGroup findByUserGroupName( final java.lang.String queryString, final java.lang.String name ) {
        java.util.List<String> argNames = new java.util.ArrayList<String>();
        java.util.List<Object> args = new java.util.ArrayList<Object>();
        args.add( name );
        argNames.add( "name" );
        java.util.Set<UserGroup> results = new java.util.LinkedHashSet<UserGroup>( this.getHibernateTemplate()
                .findByNamedParam( queryString, argNames.toArray( new String[argNames.size()] ), args.toArray() ) );
        Object result = null;
        if ( results.size() > 1 ) {
            throw new org.springframework.dao.InvalidDataAccessResourceUsageException(
                    "More than one instance of 'UserGroup" + "' was found when executing query --> '" + queryString
                            + "'" );
        } else if ( results.size() == 1 ) {
            result = results.iterator().next();
        }

        return ( UserGroup ) result;
    }

    @Override
    public Collection<? extends UserGroup> load( Collection<Long> ids ) {
        return this.getHibernateTemplate().findByNamedParam( "from UserGroupImpl where id in (:ids)", "ids", ids );
    }

    /**
     * @see UserGroupDao#load(int, java.lang.Long)
     */

    @Override
    public UserGroup load( final java.lang.Long id ) {
        if ( id == null ) {
            throw new IllegalArgumentException( "UserGroup.load - 'id' can not be null" );
        }
        final Object entity = this.getHibernateTemplate().get( UserGroupImpl.class, id );
        return ( UserGroup ) entity;
    }

    /**
     * @see UserGroupDao#loadAll(int)
     */

    @Override
    public java.util.Collection<? extends UserGroup> loadAll() {
        final Collection<? extends UserGroup> results = this.getHibernateTemplate().loadAll( UserGroupImpl.class );

        return results;
    }

    /**
     * @see ubic.gemma.model.common.SecurableDao#remove(java.util.Collection)
     */

    @Override
    public void remove( java.util.Collection<? extends UserGroup> entities ) {
        if ( entities == null ) {
            throw new IllegalArgumentException( "UserGroup.remove - 'entities' can not be null" );
        }
        this.getHibernateTemplate().deleteAll( entities );
    }

    /**
     * @see ubic.gemma.model.common.SecurableDao#update(java.util.Collection)
     */

    @Override
    public void update( final java.util.Collection<? extends UserGroup> entities ) {
        if ( entities == null ) {
            throw new IllegalArgumentException( "UserGroup.update - 'entities' can not be null" );
        }
        this.getHibernateTemplate().executeWithNativeSession(
                new org.springframework.orm.hibernate3.HibernateCallback<UserGroup>() {
                    @Override
                    public UserGroup doInHibernate( org.hibernate.Session session )
                            throws org.hibernate.HibernateException {
                        for ( java.util.Iterator<? extends UserGroup> entityIterator = entities.iterator(); entityIterator
                                .hasNext(); ) {
                            update( entityIterator.next() );
                        }
                        return null;
                    }
                } );
    }

}