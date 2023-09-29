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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * @author paul
 * @version $Id: AclServiceImpl.java,v 1.1 2013/09/14 16:55:19 paul Exp $
 */
public class AclServiceImpl implements AclService {

    private static final Log log = LogFactory.getLog( AclDaoImpl.class );

    private final AclDao aclDao;

    public AclServiceImpl( AclDao aclDao ) {
        this.aclDao = aclDao;
    }

    @Override
    @Transactional
    public MutableAcl createAcl( ObjectIdentity objectIdentity ) throws AlreadyExistsException {
        Assert.isInstanceOf( AclObjectIdentity.class, objectIdentity );

        AclObjectIdentity aclObjectIdentity = ( AclObjectIdentity ) objectIdentity;

        // Check this object identity hasn't already been persisted (fast) or there's already a type/identifier registered (slow)
        if ( aclObjectIdentity.getId() != null || aclDao.findObjectIdentity( aclObjectIdentity ) != null ) {
            throw new AlreadyExistsException( "Object identity '" + objectIdentity + "' already exists in the database" );
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL (can be changed later on)
        if ( aclObjectIdentity.getOwnerSid() == null ) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            AclPrincipalSid owner = new AclPrincipalSid( auth );
            log.trace( String.format( "%s has no owner, assigning it to %s", aclObjectIdentity, owner ) );
            aclObjectIdentity.setOwnerSid( owner );
        }

        // create the SID
        if ( aclObjectIdentity.getOwnerSid().getId() == null ) {
            log.trace( String.format( "Owner of %s does not have an ID, finding or creating it...", aclObjectIdentity ) );
            aclObjectIdentity.setOwnerSid( aclDao.findOrCreateSid( aclObjectIdentity.getOwnerSid() ) );
        }

        // if the parent is identified by type/identifier, we have to retrieve it
        // we don't create parent ACLs however
        if ( aclObjectIdentity.getParentObject() != null && aclObjectIdentity.getParentObject().getId() == null ) {
            log.trace( String.format( "Parent of %s does not have an ID, finding or creating it...", aclObjectIdentity ) );
            aclObjectIdentity.setParentObject( requireNonNull( aclDao.findObjectIdentity( aclObjectIdentity.getParentObject() ),
                "Could not find parent of " + aclObjectIdentity ) );
        }

        // Create the acl_object_identity row
        objectIdentity = aclDao.createObjectIdentity( aclObjectIdentity );

        return ( MutableAcl ) this.readAclById( objectIdentity );
    }

    @Override
    @Transactional
    public void deleteAcl( ObjectIdentity objectIdentity, boolean deleteChildren ) {
        Assert.isInstanceOf( AclObjectIdentity.class, objectIdentity );
        // ensure that the aoi is in the session and also handle deleting by type/identifier combo
        AclObjectIdentity aclObjectIdentity = aclDao.findObjectIdentity( ( AclObjectIdentity ) objectIdentity );
        Assert.notNull( aclObjectIdentity );
        aclDao.deleteObjectIdentity( aclObjectIdentity, deleteChildren );
    }

    @Override
    @Transactional
    public void deleteSid( Sid sid ) {
        Assert.isInstanceOf( AclSid.class, sid );
        AclSid aclSid = aclDao.findSid( ( AclSid ) sid );
        Assert.notNull( aclSid );
        aclDao.deleteSid( aclSid );
    }

    @Override
    @Transactional(readOnly = true)
    public List<ObjectIdentity> findChildren( final ObjectIdentity parentIdentity ) {
        Assert.isInstanceOf( AclObjectIdentity.class, parentIdentity );
        return new ArrayList<>( aclDao.findChildren( ( AclObjectIdentity ) parentIdentity ) );
    }

    @Override
    @Transactional(readOnly = true, noRollbackFor = NotFoundException.class)
    public Acl readAclById( ObjectIdentity object ) throws NotFoundException {
        return doReadAcls( Collections.singletonList( object ), null ).get( object );
    }

    @Override
    @Transactional(readOnly = true, noRollbackFor = NotFoundException.class)
    public Acl readAclById( ObjectIdentity object, List<Sid> sids ) throws NotFoundException {
        return doReadAcls( Collections.singletonList( object ), sids ).get( object );
    }

    @Override
    @Transactional(readOnly = true, noRollbackFor = NotFoundException.class)
    public Map<ObjectIdentity, Acl> readAclsById( List<ObjectIdentity> objects ) throws NotFoundException {
        return doReadAcls( objects, null );
    }

    @Override
    @Transactional(readOnly = true, noRollbackFor = NotFoundException.class)
    public Map<ObjectIdentity, Acl> readAclsById( final List<ObjectIdentity> objects, final List<Sid> sids ) throws NotFoundException {
        return doReadAcls( objects, sids );
    }

    @Override
    @Transactional
    public MutableAcl updateAcl( final MutableAcl acl ) throws NotFoundException {
        Assert.notNull( acl.getId(), "Object Identity doesn't provide an identifier" );
        Assert.isInstanceOf( AclObjectIdentity.class, acl.getObjectIdentity() );
        Assert.isInstanceOf( AclSid.class, acl.getOwner() );
        if ( ( ( AclSid ) acl.getOwner() ).getId() == null ) {
            log.trace( String.format( "Owner of %s does not have an ID, finding or creating it...", acl ) );
            acl.setOwner( aclDao.findOrCreateSid( ( AclSid ) acl.getOwner() ) );
        }
        aclDao.updateObjectIdentity( ( AclObjectIdentity ) acl.getObjectIdentity(), acl );
        return acl;
    }

    private Map<ObjectIdentity, Acl> doReadAcls( final List<ObjectIdentity> objects, @Nullable final List<Sid> sids ) throws NotFoundException {
        if ( objects.isEmpty() ) {
            return Collections.emptyMap();
        }
        Map<ObjectIdentity, Acl> result = aclDao.readAclsById( objects, sids );
        if ( result.isEmpty() ) {
            if ( objects.size() == 1 ) {
                throw new NotFoundException( String.format( "Unable to find ACL information for %s.", objects.iterator().next() ) );
            } else {
                throw new NotFoundException( "Unable to find ACL information for any of the supplied object identities." );
            }
        }
        return result;
    }
}
