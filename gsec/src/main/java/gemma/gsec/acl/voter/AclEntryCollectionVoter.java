/*
 * The Gemma_sec1 project
 *
 * Copyright (c) 2009 University of British Columbia
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
package gemma.gsec.acl.voter;

import gemma.gsec.acl.domain.AclService;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAclVoter;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.util.TypeUtils;

import java.lang.reflect.GenericArrayType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Customized voter that looks at collections to see if permissions are present for objects contained in the collection;
 * the processDomainObjectClass set refers to the types of objects in the collection. getInternalMethod refers to a
 * method that will be applied to the contained object -- not the collection. Other settings (sidRetrievalStrategy etc)
 * work exactly like the superclass.
 * <p>
 * Method invocation works like this: As for the AclEntryVoter, this only handles cases where there is a single matching
 * argument. Each argument is checked in order; if it's a collection, its contents are examined; If the collection
 * contains objects matching the configured processDomainObjectClass, then it is used. If the collection is empty, it is
 * ignored. If no Collection of processDomainObjectClass is found, a AuthorizationServiceException is thrown. The
 * limitation that the collection be non-empty is so there is some way to tell what the intent is.
 * <p>
 * The voting works as follows: The Principal must have the required Permissions on <em>all</em> of the collection's
 * members; otherwise DENIED. ABSTAIN will be returned if it isn't a Collection in the first place. Null collection
 * members are ignored. As with the superclass, an exception will be thrown if the collection members are not of the set
 * processDomainObjectClass type.
 *
 * @author paul
 * @version $Id: AclCollectionEntryVoter.java,v 1.6 2013/09/14 16:56:03 paul Exp $
 * @see org.springframework.security.acls.AclEntryVoter -- this is basically the same thing with a revised vote method;
 * I would have subclassed it if there weren't so many private fields there.
 */
public class AclEntryCollectionVoter extends AbstractAclVoter {

    private static final Log logger = LogFactory.getLog( AclEntryCollectionVoter.class );

    private final AclService aclService;
    private final String processConfigAttribute;
    private final Permission[] requirePermission;

    private SidRetrievalStrategy sidRetrievalStrategy;
    private ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy;

    public AclEntryCollectionVoter( AclService aclService, String processConfigAttribute, Permission[] requirePermission ) {
        this.aclService = aclService;
        this.processConfigAttribute = processConfigAttribute;
        this.requirePermission = requirePermission;
    }

    @Override
    public boolean supports( ConfigAttribute attribute ) {
        return attribute.getAttribute() != null && attribute.getAttribute().equals( processConfigAttribute );
    }

    /*
     * Most of this is modified from the superclass vote method code.
     *
     * @see org.springframework.security.acls.AclEntryVoter#vote(org.springframework.security.core.Authentication,
     * java.lang.Object, java.util.Collection)
     */
    @Override
    public int vote( Authentication authentication, MethodInvocation object, Collection<ConfigAttribute> attributes ) {
        for ( ConfigAttribute attr : attributes ) {
            if ( !this.supports( attr ) ) {
                continue;
            }

            /*
             * This is what makes the decision on the invocation
             */
            Collection<?> coll = getCollectionInstance( object );

            if ( coll == null ) {
                return ACCESS_ABSTAIN;
            }

            List<ObjectIdentity> ids = coll.stream()
                .filter( Objects::nonNull )
                .map( objectIdentityRetrievalStrategy::getObjectIdentity )
                .collect( Collectors.toList() );

            // if there are some null elements, the voter will abstain
            boolean shouldAbstain = ids.size() < coll.size();

            Map<ObjectIdentity, Acl> acls = aclService.readAclsById( ids );

            List<Sid> sids = sidRetrievalStrategy.getSids( authentication );

            for ( ObjectIdentity oid : ids ) {
                Acl acl = acls.get( oid );
                if ( acl != null ) {
                    if ( !acl.isGranted( Arrays.asList( requirePermission ), sids, false ) ) {
                        logger.debug( "Voting to deny access - at least one element was denied" );
                        return ACCESS_DENIED;
                    }
                } else {
                    if ( logger.isDebugEnabled() ) {
                        logger.debug( String.format( "Voting to deny access - no ACL were found for %s", oid ) );
                    }
                    return ACCESS_DENIED;
                }
            }

            if ( shouldAbstain ) {
                logger.debug( "Voting to abstain - at least one element was null" );
                return ACCESS_ABSTAIN;
            } else {
                logger.debug( "Voting to grant access - all elements of the collection were granted" );
                return ACCESS_GRANTED;
            }
        }

        // No configuration attribute matched, so abstain
        return ACCESS_ABSTAIN;
    }

    public void setSidRetrievalStrategy( SidRetrievalStrategy sidRetrievalStrategy ) {
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }

    public void setObjectIdentityRetrievalStrategy( ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy ) {
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    /**
     * Get the collection from the invocation.
     */
    protected Collection<?> getCollectionInstance( MethodInvocation secureObject ) {

        Object[] args;
        Class<?>[] params;
        Type[] types;

        params = secureObject.getMethod().getParameterTypes();
        types = secureObject.getMethod().getGenericParameterTypes();
        args = secureObject.getArguments();

        for ( int i = 0; i < params.length; i++ ) {
            Collection<?> coll;
            Type elementType;
            if ( Collection.class.isAssignableFrom( params[i] ) && types[i] instanceof ParameterizedType ) {
                elementType = ( ( ParameterizedType ) types[i] ).getActualTypeArguments()[0];
                coll = ( Collection<?> ) args[i];
            } else if ( types[i] instanceof GenericArrayType ) {
                elementType = ( ( GenericArrayType ) types[i] ).getGenericComponentType();
                coll = args[i] != null ? Arrays.asList( ( Object[] ) args[i] ) : null;
            } else {
                continue;
            }

            if ( TypeUtils.isAssignable( this.getProcessDomainObjectClass(), elementType ) ) {
                return coll;
            }
        }

        throw new AuthorizationServiceException( "Secure object: " + secureObject
            + " did not provide a Collection of " + this.getProcessDomainObjectClass() + "'s" );
    }
}