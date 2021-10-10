/*
 * The Gemma project
 *
 * Copyright (c) 2008-2010 University of British Columbia
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
package gemma.gsec.acl.afterinvocation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.afterinvocation.AbstractAclProvider;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

import gemma.gsec.SecurityService;
import gemma.gsec.acl.ValueObjectAwareIdentityRetrievalStrategyImpl;
import gemma.gsec.model.Securable;

/**
 * Subclass this when you want to filter collections based not on the security of the object itself, but by an
 * associated object. For example, a collection of CompositeSequences is filtered based on security of the associated
 * ArrayDesign.
 *
 * @author Paul
 * @version $Id: ByAssociationFilteringProvider.java,v 1.5 2013/09/14 16:56:01 paul Exp $
 */
public abstract class ByAssociationFilteringProvider<T extends Securable, A> extends AbstractAclProvider {

    protected static final Log logger = LogFactory.getLog( ByAssociationFilteringProvider.class );
    @Autowired
    private SecurityService securityService;

    public ByAssociationFilteringProvider( AclService aclService, String processConfigAttribute,
            List<Permission> requirePermission ) {
        super( aclService, processConfigAttribute, requirePermission );
        this.setObjectIdentityRetrievalStrategy( new ValueObjectAwareIdentityRetrievalStrategyImpl() );
    }

    /**
     * Decides whether user has access to object based on owning object (for composition relationships).
     *
     * @param authentication
     * @param object
     * @param config
     * @param returnedObject
     * @return Object
     * @throws AccessDeniedException
     */
    @Override
    @SuppressWarnings("unchecked")
    public final Object decide( final Authentication authentication, Object object, Collection<ConfigAttribute> config,
            Object returnedObject ) throws AccessDeniedException {

        Iterator<ConfigAttribute> iter = config.iterator();

        while ( iter.hasNext() ) {
            ConfigAttribute attr = iter.next();

            if ( this.supports( attr ) ) {
                // Need to process the Collection for this invocation
                if ( returnedObject == null ) {
                    if ( logger.isDebugEnabled() ) {
                        logger.debug( "Return object is null, skipping" );
                    }

                    return null;
                }

                Filterer<A> filterer = null;

                boolean wasSingleton = false;
                if ( returnedObject instanceof Collection ) {
                    Collection<A> collection = ( Collection<A> ) returnedObject;
                    filterer = new CollectionFilterer<>( collection );
                } else if ( returnedObject.getClass().isArray() ) {
                    A[] array = ( A[] ) returnedObject;
                    filterer = new ArrayFilterer<>( array );
                } else {
                    // shortcut, just put the object in a collection. (PP)
                    wasSingleton = true;
                    Collection<A> coll = new HashSet<>();
                    coll.add( ( A ) returnedObject );
                    filterer = new CollectionFilterer<>( coll );
                }

                List<Boolean> hasPerms = getDomainObjectPermissionDecisions( authentication, filterer );
                filter( filterer, hasPerms );

                if ( wasSingleton ) {
                    if ( ( ( Collection<A> ) filterer.getFilteredObject() ).size() == 1 ) {
                        return ( ( Collection<A> ) filterer.getFilteredObject() ).iterator().next();
                    }
                    return null;

                }
                return filterer.getFilteredObject();
            }
        }

        return returnedObject;
    }

    public abstract String getProcessConfigAttribute();

    /**
     * This base implementation supports any type of class, because it does not query the presented secure object.
     * Subclasses can provide a more specific implementation.
     *
     * @param clazz the secure object
     * @return always <code>true</code>
     */
    @Override
    public boolean supports( Class<?> clazz ) {
        return true;
    }

    /**
     * Called by the AbstractSecurityInterceptor at startup time to determine of AfterInvocationManager can process the
     * ConfigAttribute.
     *
     * @param attribute
     * @return boolean
     */
    @Override
    public final boolean supports( ConfigAttribute attribute ) {
        return ( attribute.getAttribute() != null ) && attribute.getAttribute().equals( getProcessConfigAttribute() );
    }

    /**
     * Given one of the input objects (which is not securable) return the associated securable.
     *
     * @param targetDomainObject
     * @return
     */
    protected abstract T getAssociatedSecurable( Object targetDomainObject );

    /**
     * @param filterer
     * @param hasPerms
     */
    private void filter( Filterer<A> filterer, List<Boolean> hasPerms ) {
        int i = 0;
        for ( A targetDomainObject : filterer ) {
            T domainObject = getAssociatedSecurable( targetDomainObject );
            boolean hasPermission = false;

            if ( domainObject == null ) {
                hasPermission = true;
            } else {
                hasPermission = hasPerms.get( i );
            }

            if ( !hasPermission ) {
                filterer.remove( targetDomainObject );

                if ( logger.isDebugEnabled() ) {
                    logger.debug( "Principal is NOT authorised for element: " + targetDomainObject );
                }
            }
            i++;
        }
    }

    /**
     * Save time by getting the associated (parent) domain objects. Often there is just one; or a small number compared
     * to the large number of targetdomainobjects.
     * <p>
     * Problem: I wanted to use a Set so I would check permissions for the minimum number of objects. However, we're not
     * in a transaction here, so the Securables are often proxies. So we can't hash them.
     *
     * @param authentication
     * @param filterer
     * @return list of booleans in same order as the filterer's iterator. True if haspermissions, false otherwise.
     */
    private List<Boolean> getDomainObjectPermissionDecisions( Authentication authentication, Filterer<A> filterer ) {
        // collect up the securables.
        Iterator<A> collectionIter = filterer.iterator();
        List<T> domainObjects = new ArrayList<>( 100 );
        while ( collectionIter.hasNext() ) {
            A targetDomainObject = collectionIter.next();
            T domainObject = getAssociatedSecurable( targetDomainObject );
            domainObjects.add( domainObject );
        }

        List<Boolean> hasPerm = securityService.hasPermission( domainObjects, this.requirePermission, authentication );
        return hasPerm;
    }
}
