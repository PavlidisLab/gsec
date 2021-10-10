/*
 * The gsec project
 *
 * Copyright (c) 2013 University of British Columbia
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
import java.util.List;

import org.apache.commons.lang3.time.StopWatch;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.afterinvocation.AbstractAclProvider;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

import gemma.gsec.SecurityService;
import gemma.gsec.acl.ValueObjectAwareIdentityRetrievalStrategyImpl;
import gemma.gsec.model.Securable;

/**
 * Overrides the functionality of the spring-provided AclEntryAfterInvocationCollectionFilteringProvider to be more
 * efficient with large collections.
 *
 * @author Paul
 * @version $Id$
 */
public class AclEntryAfterInvocationCollectionFilteringProvider<A extends Securable> extends AbstractAclProvider {

    private static final Log log = LogFactory.getLog( AclEntryAfterInvocationCollectionFilteringProvider.class );

    @Autowired
    private SecurityService securityService;

    public AclEntryAfterInvocationCollectionFilteringProvider( AclService aclService, List<Permission> requirePermission ) {
        super( aclService, "AFTER_ACL_COLLECTION_READ", requirePermission );
        this.setObjectIdentityRetrievalStrategy( new ValueObjectAwareIdentityRetrievalStrategyImpl() );
    }

    @Override
    @SuppressWarnings("unchecked")
    public Object decide( Authentication authentication, Object object, Collection<ConfigAttribute> config,
            Object returnedObject ) throws AccessDeniedException {

        if ( returnedObject == null ) {
            // log.debug( "Return object is null, skipping (target=" + object + ")" );
            return null;
        }

        for ( ConfigAttribute attr : config ) {
            if ( !this.supports( attr ) ) {
                continue;
            }

            // Need to process the Collection for this invocation
            Filterer<A> filterer;

            if ( returnedObject instanceof Collection ) {
                filterer = new CollectionFilterer<>( ( Collection<A> ) returnedObject );
            } else if ( returnedObject.getClass().isArray() ) {
                filterer = new ArrayFilterer<>( ( A[] ) returnedObject );
            } else {
                throw new AuthorizationServiceException( "A Collection or an array (or null) was required as the "
                        + "returnedObject, but the returnedObject was: " + returnedObject );
            }

            StopWatch timer = new StopWatch();
            timer.start();
            /*
             * Collect up the securables
             */
            List<Securable> domainObjects = new ArrayList<>();
            for ( Object domainObject : filterer ) {
                if ( !Securable.class.isAssignableFrom( domainObject.getClass() ) ) {
                    continue;
                }
                domainObjects.add( ( Securable ) domainObject );
            }

            // bulk fetch...
            List<Boolean> hasPerms = securityService.hasPermission( domainObjects, this.requirePermission,
                    authentication );

            filter( filterer, hasPerms );

            return filterer.getFilteredObject();
        }

        return returnedObject;
    }

    protected void filter( Filterer<A> filterer, List<Boolean> hasPerms ) {
        int i = 0;
        for ( A domainObject : filterer ) {
            boolean hasPermission = false;

            if ( domainObject == null ) {
                hasPermission = true;
            } else {
                hasPermission = hasPerms.get( i );
            }

            if ( !hasPermission ) {
                filterer.remove( domainObject );

                if ( log.isTraceEnabled() ) {
                    log.trace( "Principal is NOT authorised for element: " + domainObject );
                }
            }
            i++;
        }
    }
}
