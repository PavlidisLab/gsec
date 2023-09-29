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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hibernate.Hibernate;
import org.hibernate.ObjectNotFoundException;
import org.hibernate.SessionFactory;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;
import org.springframework.security.util.FieldUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;

import static java.util.Objects.requireNonNull;

/**
 * We have our own implementation of the AclDao in part because of deadlock problems caused by the default JDBC-based
 * spring security DAO. As documented here:
 * <a href="http://www.ericsimmerman.com/2012/06/resolving-spring-security-acl-deadlock.html">...</a>:
 * </p>
 * <blockquote> The default JDBCTemplate based implementation of Spring Security ACLs removes and recreates the entire
 * ACL for each update. That requires both deletes and inserts into the same table within the same JPA transaction and
 * is a recipe for deadlock when using the default MySQL transaction isolation level of REPEATABLE_READ. </blockquote>
 *
 * @author Paul
 */
public class AclDaoImpl implements AclDao {

    private static final Log log = LogFactory.getLog( AclDaoImpl.class );

    private final SessionFactory sessionFactory;
    private final AclAuthorizationStrategy aclAuthorizationStrategy;
    private final PermissionGrantingStrategy permissionGrantingStrategy;
    private final PermissionFactory permissionFactory = new DefaultPermissionFactory();

    public AclDaoImpl( SessionFactory sessionFactory, AclAuthorizationStrategy aclAuthorizationStrategy, PermissionGrantingStrategy permissionGrantingStrategy ) {
        this.sessionFactory = sessionFactory;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.permissionGrantingStrategy = permissionGrantingStrategy;
    }

    @Override
    public AclObjectIdentity findObjectIdentity( AclObjectIdentity oid ) {
        // fast path if we know the ID
        if ( oid.getId() != null ) {
            return ( AclObjectIdentity ) sessionFactory.getCurrentSession()
                .get( AclObjectIdentity.class, oid.getId() );
        }
        Assert.notNull( oid.getType() );
        Assert.notNull( oid.getIdentifier() );
        return ( AclObjectIdentity ) sessionFactory.getCurrentSession()
            .byNaturalId( AclObjectIdentity.class )
            .using( "type", oid.getType() )
            .using( "identifier", oid.getIdentifier() )
            .load();
    }


    @Override
    public AclObjectIdentity createObjectIdentity( AclObjectIdentity aoi ) {
        sessionFactory.getCurrentSession().persist( aoi );
        log.trace( "Created " + aoi );
        return aoi;
    }

    @Override
    public void deleteObjectIdentity( AclObjectIdentity objectIdentity, boolean deleteChildren ) throws ChildrenExistException {
        if ( deleteChildren ) {
            deleteObjectIdentityAndChildren( objectIdentity, 0 );
        } else if ( !hasChildren( objectIdentity ) ) {
            sessionFactory.getCurrentSession().delete( objectIdentity );
            log.trace( String.format( "Deleted %s", objectIdentity ) );
        } else {
            throw new ChildrenExistException( objectIdentity + " has children, it cannot be deleted unless deleteChildren is set to true or the children are removed beforehand." );
        }
        sessionFactory.getCurrentSession().flush();
    }

    private boolean hasChildren( AclObjectIdentity aclObjectIdentity ) {
        return ( Boolean ) sessionFactory.getCurrentSession()
            .createQuery( "select count(*) > 0 from AclObjectIdentity where parentObject = :po" )
            .setParameter( "po", aclObjectIdentity )
            .uniqueResult();
    }

    private void deleteObjectIdentityAndChildren( AclObjectIdentity objectIdentity, int indentSize ) {
        String indent = String.join( "", Collections.nCopies( indentSize, "\t" ) );
        log.trace( String.format( indent + "Deleted %s", objectIdentity ) );
        List<AclObjectIdentity> c = findChildren( objectIdentity );
        for ( AclObjectIdentity cc : c ) {
            deleteObjectIdentityAndChildren( cc, indentSize + 1 );
        }
        sessionFactory.getCurrentSession().delete( objectIdentity );
    }

    @Override
    public void deleteSid( AclSid sid ) {
        Assert.notNull( sid.getId() );

        // delete any ACL entries referring to this sid
        int deletedEntries = sessionFactory.getCurrentSession()
            .createQuery( "delete from AclEntry e where e.sid = :sid" )
            .setParameter( "sid", sid )
            .executeUpdate();
        if ( deletedEntries > 0 ) {
            log.trace( String.format( "Deleted %d ACL entries owned by %s", deletedEntries, sid ) );
        }

        // delete any object identities owned by the sid
        int deletedOis = sessionFactory.getCurrentSession()
            .createQuery( "delete from AclObjectIdentity oi where oi.ownerSid = :sid  " )
            .setParameter( "sid", sid )
            .executeUpdate();
        if ( deletedOis > 0 ) {
            log.trace( String.format( "Deleted %d ACL object identities owned by %s", deletedOis, sid ) );
        }

        // now we can safely delete the sid
        sessionFactory.getCurrentSession().delete( sid );

        log.trace( "Delete: " + sid );
    }

    @Override
    public AclSid findSid( AclSid sid ) {
        if ( sid instanceof AclPrincipalSid ) {
            AclPrincipalSid p = ( AclPrincipalSid ) sid;
            if ( sid.getId() != null ) {
                return ( AclSid ) sessionFactory.getCurrentSession().get( AclPrincipalSid.class, p.getId() );
            }
            Assert.notNull( p.getPrincipal() );
            return ( AclSid ) sessionFactory.getCurrentSession()
                .createQuery( "from AclPrincipalSid where principal = :p" )
                .setParameter( "p", p.getPrincipal() )
                .uniqueResult();
        } else if ( sid instanceof AclGrantedAuthoritySid ) {
            AclGrantedAuthoritySid g = ( AclGrantedAuthoritySid ) sid;
            if ( sid.getId() != null ) {
                return ( AclSid ) sessionFactory.getCurrentSession().get( AclGrantedAuthoritySid.class, g.getId() );
            }
            Assert.notNull( g.getGrantedAuthority() );
            return ( AclSid ) sessionFactory.getCurrentSession()
                .createQuery( "from AclGrantedAuthoritySid where grantedAuthority = :g" )
                .setParameter( "g", g.getGrantedAuthority() )
                .uniqueResult();
        } else {
            throw new IllegalArgumentException( "Unsupported ACL SID type: " + sid.getClass() );
        }
    }

    @Override
    public List<AclObjectIdentity> findChildren( AclObjectIdentity parentIdentity ) {
        // fast path if we know the ID
        if ( parentIdentity.getId() != null ) {
            //noinspection unchecked
            return sessionFactory.getCurrentSession()
                .createQuery( "from AclObjectIdentity o where o.parentObject = :po" )
                .setParameter( "po", parentIdentity )
                .list();
        } else {
            Assert.notNull( parentIdentity.getType() );
            Assert.notNull( parentIdentity.getIdentifier() );
            //noinspection unchecked
            return sessionFactory.getCurrentSession()
                .createQuery( "from AclObjectIdentity o where o.parentObject.type = :type and o.parentObject.identifier = :identifier" )
                .setParameter( "type", parentIdentity.getType() )
                .setParameter( "identifier", parentIdentity.getIdentifier() )
                .list();
        }
    }

    @Override
    public AclSid createSid( AclSid sid ) {
        sessionFactory.getCurrentSession().persist( sid );
        log.trace( "Created " + sid );
        return sid;
    }

    /**
     * Note that the objects here are not persistent - they need to be populated from the db.
     * <p>
     * argument sids is ignored by this implementation
     */
    @Override
    public Map<ObjectIdentity, Acl> readAclsById( List<ObjectIdentity> objects, List<Sid> sids ) {
        Assert.notEmpty( objects, "Objects to lookup required" );

        // must use a list, otherwise the proxies will be initialized
        List<AclObjectIdentity> reloadedAclOids = new ArrayList<>();
        for ( ObjectIdentity oid : objects ) {
            Assert.isInstanceOf( AclObjectIdentity.class, oid );
            AclObjectIdentity aclOid = ( AclObjectIdentity ) oid;
            AclObjectIdentity reloadedAclOid;
            if ( aclOid.getId() != null ) {
                // load it from the first/second-level cache
                reloadedAclOid = ( AclObjectIdentity ) sessionFactory.getCurrentSession()
                    .load( AclObjectIdentity.class, aclOid.getId() );
            } else {
                // load it from the first/second-level cache using a natural ID (i.e. type + identifier)
                Assert.notNull( aclOid.getType() );
                Assert.notNull( aclOid.getIdentifier() );
                reloadedAclOid = ( AclObjectIdentity ) sessionFactory.getCurrentSession()
                    .byNaturalId( AclObjectIdentity.class )
                    .using( "type", aclOid.getType() )
                    .using( "identifier", aclOid.getIdentifier() )
                    .getReference();
                if ( reloadedAclOid == null ) {
                    // FIXME: for some reason, natural ID retrieval may return null without producing an invalid proxy
                    log.trace( "Failed to load an ACL object identity from persistent storage: "
                        + new ObjectNotFoundException( aclOid.getType() + ":" + aclOid.getIdentifier(), AclObjectIdentity.class.getName() ).getMessage() );
                    continue;
                }
            }
            reloadedAclOids.add( reloadedAclOid );
        }

        // Hibernate uses batch-fetching for proxies, and we've set batch-size in AclObjectIdentity.hbm.xml, so this
        // should be relatively efficient
        Iterator<AclObjectIdentity> iterator = reloadedAclOids.iterator();
        while ( iterator.hasNext() ) {
            AclObjectIdentity reloadedAclOid = iterator.next();
            try {
                Hibernate.initialize( reloadedAclOid );
            } catch ( ObjectNotFoundException e ) {
                log.trace( "Failed to load an ACL object identity from persistent storage: " + e.getMessage() );
                iterator.remove();
            }
        }

        // Add loaded batch (all elements 100% initialized) to results
        return loadAcls( reloadedAclOids );
    }

    /**
     * This is an important method, and one that causes problems in the default JDBC-based service from spring-security.
     */
    @Override
    public void updateObjectIdentity( AclObjectIdentity aclObjectIdentity, Acl acl ) {
        Assert.isInstanceOf( AclObjectIdentity.class, acl.getObjectIdentity() );
        Assert.isInstanceOf( AclSid.class, acl.getOwner() );
        if ( log.isTraceEnabled() )
            log.trace( ">>>>>>>>>> Starting database update of ACL for: " + acl.getObjectIdentity() );
        updateObjectIdentity( aclObjectIdentity, acl, 0 );
        // persist the changes immediately
        sessionFactory.getCurrentSession().update( aclObjectIdentity );
        sessionFactory.getCurrentSession().flush();
        if ( log.isTraceEnabled() )
            log.trace( ">>>>>>>>>> Done with database update of ACL for: " + acl.getObjectIdentity() );
    }

    private void updateObjectIdentity( AclObjectIdentity aclObjectIdentity, Acl acl, int indentSize ) {
        Assert.isInstanceOf( AclObjectIdentity.class, acl.getObjectIdentity() );
        Assert.isInstanceOf( AclSid.class, acl.getOwner() );
        Assert.notNull( ( ( AclSid ) acl.getOwner() ).getId() );
        Assert.isTrue( indentSize >= 0 );

        String indent = String.join( "", Collections.nCopies( indentSize, "\t" ) );

        log.trace( indent + "Updating ACL on " + aclObjectIdentity );

        // update sids and entries of the main object
        if ( !Objects.equals( aclObjectIdentity.getOwnerSid(), acl.getOwner() ) ) {
            if ( log.isTraceEnabled() ) {
                log.trace( indent + String.format( "Owner of %s is being changed from %s to %s", aclObjectIdentity,
                    aclObjectIdentity.getOwnerSid(), acl.getOwner() ) );
            }
        }
        aclObjectIdentity.setOwnerSid( acl.getOwner() );
        aclObjectIdentity.setEntriesInheriting( acl.isEntriesInheriting() );

        int i = 0;
        List<AclEntry> entriesFromAcl = new ArrayList<>( acl.getEntries().size() );
        for ( AccessControlEntry accessControlEntry : acl.getEntries() ) {
            AclEntry entry;
            if ( accessControlEntry.getId() != null ) {
                // this is cheap because it is already loaded
                entry = ( AclEntry ) requireNonNull( sessionFactory.getCurrentSession().get( AclEntry.class, accessControlEntry.getId() ),
                    "The following ACL entry count not be found: " + accessControlEntry );
            } else {
                entry = new AclEntry();
            }
            entry.setSid( ( AclSid ) acl.getOwner() );
            entry.setMask( accessControlEntry.getPermission().getMask() );
            entry.setGranting( accessControlEntry.isGranting() );
            entry.setAceOrder( i++ );
            entriesFromAcl.add( entry );
        }

        // update the collection of entries.
        aclObjectIdentity.getEntries().clear();
        aclObjectIdentity.getEntries().addAll( entriesFromAcl );

        // parent likely went from null -> non-null, update it
        if ( acl.getParentAcl() != null ) {
            if ( log.isTraceEnabled() )
                log.trace( indent + "Updating ACL on parent: " + acl.getParentAcl().getObjectIdentity() );
            AclObjectIdentity parentOi = ( AclObjectIdentity ) acl.getParentAcl().getObjectIdentity();
            // recursively update the parents
            updateObjectIdentity( parentOi, acl.getParentAcl(), indentSize + 1 );
            aclObjectIdentity.setParentObject( parentOi );
            assert aclObjectIdentity.getParentObject() != null;
        }

        // parent went from non-null to null, unset it
        else if ( aclObjectIdentity.getParentObject() != null ) {
            if ( log.isTraceEnabled() )
                log.trace( indent + "Unsetting parent ACL of: " + aclObjectIdentity );
            aclObjectIdentity.setParentObject( null );
        }
    }

    /**
     * Load a batch of {@link AclObjectIdentity} into a mapping of {@link ObjectIdentity} to {@link Acl}.
     * <p>
     * Due to the way {@link AclObjectIdentity} are mapped with Hibernate, they are already fully initialized, so this
     * method will proceed to populate the ACLs and their parents recursively.
     */
    private Map<ObjectIdentity, Acl> loadAcls( final Collection<AclObjectIdentity> objectIdentities ) {
        Map<ObjectIdentity, Acl> acls = new HashMap<>();
        loadAcls( objectIdentities, acls );
        return acls;
    }

    /**
     * Load ACLs when we know the primary key of the objectIdentity. Recursively fill in the parent ACLs.
     *
     * @param objectIdentities primary keys of the object identities to be fetched. If these yield acls that are the
     *                         parents of the given acls, they will be populated.
     * @param acls             the starting set of acls.
     */
    private void loadAcls( final Collection<AclObjectIdentity> objectIdentities, final Map<ObjectIdentity, Acl> acls ) {
        Assert.notNull( acls, "ACLs are required" );

        if ( objectIdentities.isEmpty() ) {
            return;
        }

        Set<AclObjectIdentity> parentAclsToLoad = new HashSet<>();
        for ( AclObjectIdentity o : objectIdentities ) {
            MutableAcl acl = new AclImpl( o, o.getId(), aclAuthorizationStrategy, permissionGrantingStrategy,
                null /* parents are filled later */, null, o.getEntriesInheriting(), o.getOwnerSid() );
            List<AclEntry> orderedEntries = new ArrayList<>( o.getEntries() );
            orderedEntries.sort( Comparator.comparing( AclEntry::getAceOrder ) );
            List<AccessControlEntry> aces = new ArrayList<>( o.getEntries().size() );
            for ( AclEntry e : orderedEntries ) {
                aces.add( new AccessControlEntryImpl( e.getId(), acl, e.getSid(), permissionFactory.buildFromMask( e.getMask() ), e.isGranting(), false, false ) );
            }
            // unfortunately, there's no way to pass a pre-constructed list of ACEs to Spring ACL implementation without
            // going through insertAce()
            FieldUtils.setProtectedFieldValue( "aces", acl, aces );
            // we call setParent() later
            if ( o.getParentObject() != null ) {
                Acl parentAcl = acls.get( o.getParentObject() );
                if ( parentAcl != null ) {
                    acl.setParent( parentAcl );
                } else {
                    parentAclsToLoad.add( o.getParentObject() );
                }
            }
            acls.put( o, acl );
        }

        // load the parent ACLs (recursively)
        loadAcls( parentAclsToLoad, acls );

        /*
         * Fill in the parent Acls for the acls that need them.
         */
        for ( AclObjectIdentity oiid : objectIdentities ) {
            MutableAcl acl = ( MutableAcl ) acls.get( oiid );
            if ( acl.getParentAcl() != null ) {
                // we already did it.
                continue;
            }
            if ( oiid.getParentObject() != null ) {
                Acl parentAcl = acls.get( oiid.getParentObject() );
                // this used to be an assertion, source of failures not clear...
                if ( parentAcl == null ) {
                    throw new IllegalStateException(
                        "ACLs did not contain key for parent object identity of " + oiid + "( parent = " + oiid.getParentObject() + "); "
                            + "ACLs being inspected: " + StringUtils.collectionToDelimitedString( acls.values(), "\n" ) );
                }
                acl.setParent( parentAcl );
            }
        }
    }
}
