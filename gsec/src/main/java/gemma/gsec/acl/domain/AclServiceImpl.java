/*
 * The Gemma project
 * 
 * Copyright (c) 2010-2013 University of British Columbia
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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/**
 * @author paul
 * @version $Id: AclServiceImpl.java,v 1.1 2013/09/14 16:55:19 paul Exp $
 */
@Component(value = "aclService")
public class AclServiceImpl implements AclService {

    private static Log log = LogFactory.getLog( AclServiceImpl.class.getName() );

    @Autowired
    private AclDao aclDao;

    private TransactionTemplate transactionTemplate;

    @Autowired
    public AclServiceImpl( PlatformTransactionManager transactionManager ) {
        assert transactionManager != null;

        /*
         * only used for read-only methods. Other methods always happen in an existing transaction. This is a bit of a
         * hack, but @Transactional annotations are not being picked up here. But this works fine.
         */

        this.transactionTemplate = new TransactionTemplate( transactionManager );
        this.transactionTemplate.setPropagationBehavior( TransactionDefinition.PROPAGATION_REQUIRES_NEW );
        this.transactionTemplate.setReadOnly( true );

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.acls.model.MutableAclService#createAcl(org.springframework.security.acls.model.
     * ObjectIdentity)
     */
    @Override
    public MutableAcl createAcl( ObjectIdentity objectIdentity ) throws AlreadyExistsException {
        assert TransactionSynchronizationManager.isActualTransactionActive();

        // Check this object identity hasn't already been persisted
        if ( find( objectIdentity ) != null ) {
            Acl acl = this.readAclById( objectIdentity );
            if ( acl != null ) {
                log.warn( "Create called on objectidentity that already exists, and acl could be loaded; " + acl );
                /*
                 * This happens ... why? When we set a parent object earlier than needed?
                 */
                // return ( MutableAcl ) acl;
            }
            throw new AlreadyExistsException( "Object identity '" + objectIdentity + "' already exists in the database" );
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL (can be changed later on)
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        AclPrincipalSid sid = new AclPrincipalSid( auth );

        // Create the acl_object_identity row
        objectIdentity = createObjectIdentity( objectIdentity, sid );

        Acl acl = this.readAclById( objectIdentity );

        return ( MutableAcl ) acl;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.acls.model.MutableAclService#deleteAcl(org.springframework.security.acls.model.
     * ObjectIdentity, boolean)
     */
    @Override
    public void deleteAcl( ObjectIdentity objectIdentity, boolean deleteChildren ) throws ChildrenExistException {
        assert TransactionSynchronizationManager.isActualTransactionActive();

        aclDao.delete( find( objectIdentity ), deleteChildren );
    }

    /**
     * Remove a sid and all associated ACEs.
     * 
     * @param sid
     */
    @Override
    @Transactional
    public void deleteSid( Sid sid ) {
        assert TransactionSynchronizationManager.isActualTransactionActive();

        aclDao.delete( sid );
    }

    @Override
    public List<ObjectIdentity> findChildren( final ObjectIdentity parentIdentity ) {

        if ( TransactionSynchronizationManager.isActualTransactionActive() ) {
            return aclDao.findChildren( parentIdentity );

        }

        return transactionTemplate.execute( new TransactionCallback<List<ObjectIdentity>>() {

            @Override
            public List<ObjectIdentity> doInTransaction( TransactionStatus status ) {
                return aclDao.findChildren( parentIdentity );
            }
        } );

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.security.acls.model.AclService#readAclById(org.springframework.security.acls.model.
     * ObjectIdentity
     * )
     */
    @Override
    public Acl readAclById( ObjectIdentity object ) throws NotFoundException {
        return readAclById( object, null );
    }

    @Override
    public Acl readAclById( ObjectIdentity object, List<Sid> sids ) throws NotFoundException {
        Map<ObjectIdentity, Acl> map = readAclsById( Arrays.asList( object ), sids );
        return map.get( object );
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.acls.model.AclService#readAclsById(java.util.List)
     */
    @Override
    public Map<ObjectIdentity, Acl> readAclsById( List<ObjectIdentity> objects ) throws NotFoundException {
        return readAclsById( objects, null );
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.acls.model.AclService#readAclsById(java.util.List, java.util.List)
     */
    @Override
    public Map<ObjectIdentity, Acl> readAclsById( final List<ObjectIdentity> objects, final List<Sid> sids )
            throws NotFoundException {

        if ( TransactionSynchronizationManager.isActualTransactionActive() ) {
            return doReadAcls( objects, sids );
        }

        return transactionTemplate.execute( new TransactionCallback<Map<ObjectIdentity, Acl>>() {

            @Override
            public Map<ObjectIdentity, Acl> doInTransaction( TransactionStatus status ) {
                // deals with cache.
                return doReadAcls( objects, sids );
            }

        } );

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.acls.model.MutableAclService#updateAcl(org.springframework.security.acls.model.
     * MutableAcl)
     */
    @Override
    public MutableAcl updateAcl( final MutableAcl acl ) throws NotFoundException {
        if ( TransactionSynchronizationManager.isActualTransactionActive() ) {
            return doUpdateAcl( acl );
        }

        return transactionTemplate.execute( new TransactionCallback<MutableAcl>() {
            @Override
            public MutableAcl doInTransaction( TransactionStatus status ) {
                // deals with cache.
                return doUpdateAcl( acl );
            }

        } );
    }

    /**
     * @param acl
     * @return
     */
    private MutableAcl doUpdateAcl( MutableAcl acl ) {
        assert TransactionSynchronizationManager.isActualTransactionActive();
        Assert.notNull( acl.getId(), "Object Identity doesn't provide an identifier" );
        aclDao.update( acl );
        return acl;
    }

    /**
     * Persist
     * 
     * @param object
     * @param owner
     * @return persistent objectIdentity (will be an AclObjectIdentity)
     */
    private AclObjectIdentity createObjectIdentity( ObjectIdentity object, Sid owner ) {
        Sid sid = createOrRetrieveSid( owner, true );
        String type = object.getType();
        return aclDao.createObjectIdentity( type, object.getIdentifier(), sid, Boolean.TRUE );
    }

    /**
     * Retrieves the primary key from acl_sid, creating a new row if needed and the allowCreate property is true.
     * 
     * @param sid to find or create
     * @param allowCreate true if creation is permitted if not found
     * @return the primary key or null if not found
     * @throws IllegalArgumentException if the <tt>Sid</tt> is not a recognized implementation.
     */
    private Sid createOrRetrieveSid( Sid sid, boolean allowCreate ) {
        if ( allowCreate ) {
            return aclDao.findOrCreate( sid );
        }
        return aclDao.find( sid );

    }

    /**
     * @param objects
     * @param sids
     * @return
     * @throws NotFoundException if any of the ACLs were not found
     */
    private Map<ObjectIdentity, Acl> doReadAcls( final List<ObjectIdentity> objects, final List<Sid> sids ) throws NotFoundException {
        Map<ObjectIdentity, Acl> result = aclDao.readAclsById( objects, sids );

        // Check every requested object identity was found (throw NotFoundException if needed)
        for ( int i = 0; i < objects.size(); i++ ) {
            ObjectIdentity key = objects.get( i );

            if ( !result.containsKey( key ) ) {
                log.debug( "ACL result size " + result.keySet().size() );
                if ( result.keySet().size() > 0 ) {
                    log.debug( "ACL result first key " + result.keySet().iterator().next() );
                }
                throw new NotFoundException( "Unable to find ACL information for object identity '" + key + "'" );
            }

            assert result.get( key ) != null;
        }

        return result;
    }

    private ObjectIdentity find( ObjectIdentity oid ) {
        AclObjectIdentity acloi = aclDao.find( oid );
        return acloi;
    }

}
