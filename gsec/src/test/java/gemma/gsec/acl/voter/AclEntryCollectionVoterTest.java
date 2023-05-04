package gemma.gsec.acl.voter;

import gemma.gsec.acl.domain.AclService;
import gemma.gsec.model.Securable;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.SimpleMethodInvocation;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AclEntryCollectionVoterTest {


    public static class Model implements Securable {

        @Override
        public Long getId() {
            return 1L;
        }
    }

    public static class MyService {

        public void test( Collection<Securable> securables ) {
        }
    }

    private AclService aclService;
    private AclEntryCollectionVoter voter;
    private ConfigAttribute ca;
    private Authentication auth;

    @Before
    public void setUp() {
        aclService = mock( AclService.class );
        voter = new AclEntryCollectionVoter( aclService, "ACL_SECURABLE_COLLECTION_READ", new Permission[] { BasePermission.READ } );
        voter.setObjectIdentityRetrievalStrategy( new ObjectIdentityRetrievalStrategyImpl() );
        voter.setSidRetrievalStrategy( new SidRetrievalStrategyImpl() );
        voter.setProcessDomainObjectClass( Securable.class );
        ca = mock( ConfigAttribute.class );
        when( ca.getAttribute() ).thenReturn( "ACL_SECURABLE_COLLECTION_READ" );
        auth = new TestingAuthenticationToken( "bob", "1234" );
    }

    @Test
    public void testCollection() throws NoSuchMethodException {
        Acl acl = mock( Acl.class );
        when( acl.isGranted( any(), any(), anyBoolean() ) ).thenReturn( true );
        when( aclService.readAclsById( any() ) )
            .thenAnswer( a -> a.getArgument( 0, Collection.class ).stream()
                .collect( Collectors.toMap( o -> ( ObjectIdentity ) o, o -> acl ) ) );
        Collection<?> collection = Collections.singleton( mock( Securable.class ) );
        Method method = MyService.class.getMethod( "test", Collection.class );
        int result = voter.vote( auth, new SimpleMethodInvocation( null, method, collection ), Collections.singletonList( ca ) );
        assertEquals( AccessDecisionVoter.ACCESS_GRANTED, result );
    }

    @Test
    public void testCollectionWhenOneEntryDoesNotGrant() throws NoSuchMethodException {
        Acl acl = mock( Acl.class );
        when( acl.isGranted( any(), any(), anyBoolean() ) ).thenReturn( true );
        when( aclService.readAclsById( any() ) )
            .thenAnswer( a -> a.getArgument( 0, Collection.class ).stream()
                .collect( Collectors.toMap( o -> ( ObjectIdentity ) o, o -> acl ) ) );
        Collection<?> collection = Collections.singleton( mock( Securable.class ) );
        Method method = MyService.class.getMethod( "test", Collection.class );
        int result = voter.vote( auth, new SimpleMethodInvocation( null, method, collection ), Collections.singletonList( ca ) );
        assertEquals( AccessDecisionVoter.ACCESS_GRANTED, result );
    }

    @Test
    public void testCollectionWhenOneEntryAbstain() throws NoSuchMethodException {
        Acl acl = mock( Acl.class );
        when( acl.isGranted( any(), any(), anyBoolean() ) ).thenReturn( true );
        when( aclService.readAclsById( any() ) )
            .thenAnswer( a -> a.getArgument( 0, Collection.class ).stream()
                .collect( Collectors.toMap( o -> ( ObjectIdentity ) o, o -> acl ) ) );
        Collection<?> collection = Collections.singleton( mock( Securable.class ) );
        Method method = MyService.class.getMethod( "test", Collection.class );
        int result = voter.vote( auth, new SimpleMethodInvocation( null, method, collection ), Collections.singletonList( ca ) );
        assertEquals( AccessDecisionVoter.ACCESS_GRANTED, result );
    }

    @Test
    public void testEmptyCollectionShouldGrant() throws NoSuchMethodException {
        Collection<?> collection = Collections.emptyList();
        Method method = MyService.class.getMethod( "test", Collection.class );
        int result = voter.vote( auth, new SimpleMethodInvocation( null, method, collection ), Collections.singletonList( ca ) );
        assertEquals( AccessDecisionVoter.ACCESS_GRANTED, result );
    }
}