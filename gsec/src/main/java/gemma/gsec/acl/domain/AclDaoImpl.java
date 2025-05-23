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
import org.hibernate.FlushMode;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Criterion;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.hibernate.sql.JoinType;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.util.Assert;

import java.io.Serializable;
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
    private final AclCache aclCache;

    public AclDaoImpl( SessionFactory sessionFactory, AclAuthorizationStrategy aclAuthorizationStrategy, AclCache aclCache ) {
        this.sessionFactory = sessionFactory;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.aclCache = aclCache;
    }

    @Override
    public AclObjectIdentity createObjectIdentity( String type, Serializable identifier, AclSid sid, boolean entriesInheriting ) {
        AclObjectIdentity aoi = new AclObjectIdentity( type, ( Long ) identifier );
        aoi.setOwnerSid( sid );
        aoi.setEntriesInheriting( entriesInheriting );
        sessionFactory.getCurrentSession().persist( aoi );
        log.trace( String.format( "Created %s", aoi ) );
        return aoi;
    }

    @Override
    public void delete( AclObjectIdentity objectIdentity, boolean deleteChildren ) {
        if ( deleteChildren ) {
            List<AclObjectIdentity> c = findChildren( objectIdentity );
            for ( AclObjectIdentity cc : c ) {
                delete( cc, true );
            }
        }

        // must do this first...
        this.evictFromCache( objectIdentity );

        sessionFactory.getCurrentSession().delete( objectIdentity );
        log.trace( String.format( "Deleted %s", objectIdentity ) );
    }

    @Override
    public void delete( AclSid sid ) {
        // delete any objectidentities owned
        //noinspection unchecked
        List<AclObjectIdentity> ownedOis = sessionFactory.getCurrentSession()
            .createQuery( "select s from AclObjectIdentity oi join oi.ownerSid s where s = :sid" )
            .setParameter( "sid", sid )
            .list();

        if ( !ownedOis.isEmpty() ) {
            for ( AclObjectIdentity oi : ownedOis ) {
                this.evictFromCache( oi );
                sessionFactory.getCurrentSession().delete( oi );
            }
        }

        // delete any aclentries referring to this sid
        //noinspection unchecked
        List<AclEntry> entries = sessionFactory.getCurrentSession()
            .createQuery( "select e from AclEntry e where e.sid = :sid" )
            .setParameter( "sid", sid )
            .list();

        for ( AclEntry e : entries ) {
            sessionFactory.getCurrentSession().delete( e );
        }

        sessionFactory.getCurrentSession().delete( sid );

    }

    @Override
    public AclObjectIdentity find( ObjectIdentity oid ) {
        return find( oid, sessionFactory.getCurrentSession() );
    }

    @Override
    public AclObjectIdentity find( ObjectIdentity oid, Session session ) {
        if ( oid instanceof AclObjectIdentity ) {
            AclObjectIdentity aoi = ( AclObjectIdentity ) oid;
            if ( aoi.getId() != null ) {
                return ( AclObjectIdentity ) sessionFactory.getCurrentSession().get( AclObjectIdentity.class, aoi.getId() );
            }
        }
        return ( AclObjectIdentity ) session
            .createQuery( "from AclObjectIdentity where type=:t and identifier=:i" )
            .setParameter( "t", oid.getType() )
            .setParameter( "i", oid.getIdentifier() )
            .setCacheable( true )
            .uniqueResult();
    }

    @Override
    public AclSid find( Sid sid ) {
        return find( sid, sessionFactory.getCurrentSession() );
    }

    @Override
    public AclSid find( Sid sid, Session session ) {
        if ( sid instanceof PrincipalSid ) {
            PrincipalSid p = ( PrincipalSid ) sid;
            return ( AclSid ) session
                .createQuery( "from AclPrincipalSid where principal = :p" )
                .setParameter( "p", p.getPrincipal() )
                .setCacheable( true )
                .uniqueResult();
        } else if ( sid instanceof GrantedAuthoritySid ) {
            GrantedAuthoritySid g = ( GrantedAuthoritySid ) sid;
            return ( AclSid ) session
                .createQuery( "from AclGrantedAuthoritySid where grantedAuthority = :g" )
                .setParameter( "g", g.getGrantedAuthority() )
                .setCacheable( true )
                .uniqueResult();
        } else if ( sid instanceof AclPrincipalSid ) {
            AclPrincipalSid p = ( AclPrincipalSid ) sid;
            if ( p.getId() != null ) {
                return ( AclSid ) session.get( AclPrincipalSid.class, p.getId() );
            }
            return ( AclSid ) session
                .createQuery( "from AclPrincipalSid where principal = :p" )
                .setParameter( "p", p.getPrincipal() )
                .setCacheable( true )
                .uniqueResult();
        } else if ( sid instanceof AclGrantedAuthoritySid ) {
            AclGrantedAuthoritySid g = ( AclGrantedAuthoritySid ) sid;
            if ( g.getId() != null ) {
                return ( AclSid ) session.get( AclGrantedAuthoritySid.class, g.getId() );
            }
            return ( AclSid ) session
                .createQuery( "from AclGrantedAuthoritySid where grantedAuthority = :g" )
                .setParameter( "g", g.getGrantedAuthority() )
                .setCacheable( true )
                .uniqueResult();
        } else {
            throw new IllegalArgumentException( "Unsupported ACL SID type: " + sid.getClass() );
        }
    }

    @Override
    public List<AclObjectIdentity> findChildren( AclObjectIdentity parentIdentity ) {
        Assert.notNull( parentIdentity, "ParentIdentity cannot be null" );
        //noinspection unchecked
        return sessionFactory.getCurrentSession()
            .createQuery( "from AclObjectIdentity o where o.parentObject = :po" )
            .setParameter( "po", parentIdentity )
            .list();
    }

    @Override
    public AclSid findOrCreate( AclSid sid ) {
        AclSid fsid = this.find( sid );

        if ( fsid != null ) return fsid;

        sessionFactory.getCurrentSession().persist( sid );

        return sid;
    }

    @Override
    public Map<AclObjectIdentity, Acl> readAclsById( List<AclObjectIdentity> objects ) {
        return readAclsById( objects, sessionFactory.getCurrentSession() );
    }

    @Override
    public Map<AclObjectIdentity, Acl> readAclsById( List<AclObjectIdentity> objectIdentities, Session session ) {
        Assert.notEmpty( objectIdentities, "Objects to lookup required" );

        Map<AclObjectIdentity, Acl> result = new HashMap<>();

        Set<AclObjectIdentity> aclsToLoad = new HashSet<>();
        for ( AclObjectIdentity oid : objectIdentities ) {
            if ( result.containsKey( oid ) ) {
                continue;
            }

            // Check we don't already have this ACL in the results

            // Check cache for the present ACL entry
            Acl acl = aclCache.getFromCache( oid );
            // Ensure any cached element supports all the requested SIDs
            // (they should always, as our base impl doesn't filter on SID)
            if ( acl != null ) {
                result.put( ( AclObjectIdentity ) acl.getObjectIdentity(), acl );
                continue;
            }

            aclsToLoad.add( oid );
        }

        if ( !aclsToLoad.isEmpty() ) {
            Map<AclObjectIdentity, Acl> loadedBatch = loadAcls( aclsToLoad, session );

            // Add loaded batch (all elements 100% initialized) to results
            result.putAll( loadedBatch );

            // Add the loaded batch to the cache
            for ( Acl loadedAcl : loadedBatch.values() ) {
                aclCache.putInCache( ( MutableAcl ) loadedAcl );
            }
        }

        return result;
    }

    @Override
    public Session openSession() {
        Session currentSession = sessionFactory.getCurrentSession();
        Session session = sessionFactory.openSession();
        session.setDefaultReadOnly( currentSession.isDefaultReadOnly() );
        session.setCacheMode( currentSession.getCacheMode() );
        session.setFlushMode( currentSession.getFlushMode() );
        return session;
    }

    /**
     * This is an important method, and one that causes problems in the default JDBC-based service from spring-security.
     */
    @Override
    public void update( MutableAcl acl ) {
        if ( log.isTraceEnabled() )
            log.trace( ">>>>>>>>>> starting database update of acl for: " + acl.getObjectIdentity() );
        /*
         * This fixes problems with premature commits causing IDs to be erased on some entities.
         */
        sessionFactory.getCurrentSession().setFlushMode( FlushMode.COMMIT );

        AclObjectIdentity aclObjectIdentity = convert( acl );

        // the ObjectIdentity might already be in the session.
        aclObjectIdentity = ( AclObjectIdentity ) sessionFactory.getCurrentSession()
            .merge( aclObjectIdentity );

        if ( acl.getParentAcl() != null ) {

            if ( log.isTraceEnabled() )
                log.trace( "       Updating ACL on parent: " + acl.getParentAcl().getObjectIdentity() );

            update( ( MutableAcl ) acl.getParentAcl() );
            aclObjectIdentity.setParentObject( convert( ( MutableAcl ) acl.getParentAcl() ) );
            assert aclObjectIdentity.getParentObject() != null;
        } else {
            // should be impossible to go from non-null to null, but just in case ...
            assert aclObjectIdentity.getParentObject() == null;
        }

        sessionFactory.getCurrentSession().update( aclObjectIdentity );

        evictFromCache( aclObjectIdentity );

        // children are left out, no big deal. Eviction more important.
        this.aclCache.putInCache( convertToAcl( aclObjectIdentity ) );

        if ( log.isTraceEnabled() )
            log.trace( " >>>>>>>>>> Done with database update of acl for: " + acl.getObjectIdentity() );
    }

    /**
     * @return synched-up and partly updated AclObjectIdentity
     */
    private AclObjectIdentity convert( MutableAcl acl ) {
        assert acl instanceof AclImpl;
        assert acl.getObjectIdentity() instanceof AclObjectIdentity;

        // these come back with the ace_order filled in.
        List<AccessControlEntry> entriesFromAcl = acl.getEntries();

        // repopulate the ID of the SIDs. May not have any if this is a secured child.
        if ( log.isTraceEnabled() && !entriesFromAcl.isEmpty() )
            log.trace( "Preparing to update " + entriesFromAcl.size() + " aces on " + acl.getObjectIdentity() );
        for ( AccessControlEntry ace : entriesFromAcl ) {
            if ( log.isTraceEnabled() ) log.trace( ace );
            AclSid sid = ( AclSid ) ace.getSid();
            if ( sid.getId() == null ) {
                AclEntry aace = ( AclEntry ) ace;
                aace.setSid( this.findOrCreate( sid ) );
            }
        }

        // synched up with the ACL, partly
        AclObjectIdentity aclObjectIdentity = ( AclObjectIdentity ) acl.getObjectIdentity();

        if ( aclObjectIdentity.getOwnerSid().getId() == null ) {
            aclObjectIdentity.setOwnerSid( requireNonNull( this.find( acl.getOwner() ),
                String.format( "Failed to locate owner SID %s for %s", aclObjectIdentity.getOwnerSid(), aclObjectIdentity ) ) );
        }

        assert aclObjectIdentity.getOwnerSid() != null;

        /*
         * Update the collection of entries.
         */
        Collection<AclEntry> entriesToUpdate = aclObjectIdentity.getEntries();
        entriesToUpdate.clear();
        for ( AccessControlEntry accessControlEntry : entriesFromAcl ) {
            entriesToUpdate.add( ( AclEntry ) accessControlEntry );
        }

        return aclObjectIdentity;
    }

    /**
     * Does not check the cache;
     */
    private MutableAcl convertToAcl( AclObjectIdentity oi ) {
        return new AclImpl( oi, aclAuthorizationStrategy, oi.getParentObject() != null ? convertToAcl( oi.getParentObject() ) : null );
    }

    /**
     * ... including children, recursively.
     */
    private void evictFromCache( AclObjectIdentity aclObjectIdentity ) {
        Assert.notNull( aclObjectIdentity, "aclObjectIdentity cannot be null" );

        this.aclCache.evictFromCache( aclObjectIdentity );
        for ( AclObjectIdentity c : this.findChildren( aclObjectIdentity ) ) {
            evictFromCache( c );
        }
    }

    /**
     * Looks up a batch of <code>ObjectIdentity</code>s directly from the database, when we only know the type and
     * object's id (not the objectIdentity PK).
     * <p>
     * The caller is responsible for optimization issues, such as selecting the identities to lookup, ensuring the cache
     * doesn't contain them already, and adding the returned elements to the cache etc.
     * <p>
     * This is required to return fully valid <code>Acl</code>s, including properly-configured parent ACLs.
     *
     * @param objectIdentities a batch of OIs to fetch ACLs for.
     */
    private Map<AclObjectIdentity, Acl> loadAcls( final Collection<AclObjectIdentity> objectIdentities, Session session ) {
        // group by type so we can use in (...) clauses
        Map<String, Set<Serializable>> idsByType = new HashMap<>();
        for ( AclObjectIdentity oi : objectIdentities ) {
            idsByType.computeIfAbsent( oi.getType(), k -> new HashSet<>() )
                .add( oi.getIdentifier() );
        }

        Criterion[] clauses = new Criterion[idsByType.size()];
        int i = 0;
        for ( Map.Entry<String, Set<Serializable>> e : idsByType.entrySet() ) {
            clauses[i++] = Restrictions.and(
                Restrictions.eq( "type", e.getKey() ),
                Restrictions.in( "identifier", e.getValue() ) );
        }

        //noinspection unchecked
        List<AclObjectIdentity> queryR = session
            .createCriteria( AclObjectIdentity.class )
            // possibly has no entries yet, so left outer join?
            .createAlias( "entries", "e", JoinType.LEFT_OUTER_JOIN )
            .add( Restrictions.or( clauses ) )
            .addOrder( Order.asc( "identifier" ) )
            .addOrder( Order.asc( "e.aceOrder" ) )
            .list();

        // this is okay if we haven't added the objects yet.
        // if ( queryR.size() < objectIdentities.size() ) {
        // log.warn( "Expected " + objectIdentities.size() + " objectidentities from db, got " + queryR.size()
        // + " from db" );
        // }

        // at this point, ACLs identities and their parents are loaded, we need to create the ACLs themselves

        Map<AclObjectIdentity, Acl> resultMap = new HashMap<>();
        for ( AclObjectIdentity oi : queryR ) {
            resultMap.put( oi, convertToAclUsingCache( oi ) );
        }

        return resultMap;
    }

    /**
     * Convert to ACL, possibly using the cache.
     */
    private Acl convertToAclUsingCache( AclObjectIdentity aoi ) {
        MutableAcl acl = aclCache.getFromCache( aoi );
        if ( acl == null ) {
            acl = new AclImpl( aoi, aclAuthorizationStrategy,
                aoi.getParentObject() != null ? convertToAclUsingCache( aoi.getParentObject() ) : null );
            aclCache.putInCache( acl );
        }
        return acl;
    }
}
