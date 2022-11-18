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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author paul
 * @version $Id: AclServiceImpl.java,v 1.1 2013/09/14 16:55:19 paul Exp $
 */
@Service(value = "aclService")
@Transactional
public class AclServiceImpl implements AclService {

    private static final Log log = LogFactory.getLog( AclServiceImpl.class );

    private final AclDao aclDao;

    @Autowired
    public AclServiceImpl( AclDao aclDao ) {
        this.aclDao = aclDao;
    }

    @Override
    public MutableAcl createAcl( ObjectIdentity objectIdentity ) throws AlreadyExistsException {
        // Check this object identity hasn't already been persisted
        if ( aclDao.find( objectIdentity ) != null ) {
            Acl acl = this.readAclById( objectIdentity );
            if ( acl != null ) {
                log.warn( "Create called on object identity that already exists, and acl could be loaded; " + acl );
                /*
                 * This happens ... why? When we set a parent object earlier than needed?
                 */
                // return ( MutableAcl ) acl;
            }
            throw new AlreadyExistsException( "Object identity '" + objectIdentity + "' already exists in the database" );
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL (can be changed later on)
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        AclSid sid = new AclPrincipalSid( auth );

        // Create the acl_object_identity row
        sid = aclDao.findOrCreate( sid );
        String type = objectIdentity.getType();
        objectIdentity = aclDao.createObjectIdentity( type, objectIdentity.getIdentifier(), sid, Boolean.TRUE );

        Acl acl = this.readAclById( objectIdentity );

        return ( MutableAcl ) acl;
    }

    @Override
    public void deleteAcl( ObjectIdentity objectIdentity, boolean deleteChildren ) throws ChildrenExistException {
        aclDao.delete( aclDao.find( objectIdentity ), deleteChildren );
    }

    @Override
    public void deleteSid( Sid sid ) {
        aclDao.delete( sid );
    }

    @Override
    @Transactional(readOnly = true)
    public List<ObjectIdentity> findChildren( final ObjectIdentity parentIdentity ) {
        return aclDao.findChildren( parentIdentity );
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
    public MutableAcl updateAcl( final MutableAcl acl ) throws NotFoundException {
        Assert.notNull( acl.getId(), "Object Identity doesn't provide an identifier" );
        aclDao.update( acl );
        return acl;
    }

    private Map<ObjectIdentity, Acl> doReadAcls( final List<ObjectIdentity> objects, final List<Sid> sids ) throws NotFoundException {
        Map<ObjectIdentity, Acl> result = aclDao.readAclsById( objects, sids );

        // Check every requested object identity was found (throw NotFoundException if needed)
        for ( ObjectIdentity key : objects ) {
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
}
