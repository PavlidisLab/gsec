package gemma.gsec.acl.afterinvocation;

import gemma.gsec.acl.domain.AclService;
import gemma.gsec.model.Securable;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

public class AclEntryAfterInvocationCollectionFilteringProviderTest {

    private AclService aclService;
    private AclEntryAfterInvocationCollectionFilteringProvider voter;
    private ConfigAttribute ca;
    private Authentication auth;

    @Before
    public void setUp() {
        aclService = mock( AclService.class );
        voter = new AclEntryAfterInvocationCollectionFilteringProvider( aclService, "ACL_SECURABLE_COLLECTION_READ", Collections.singletonList( BasePermission.READ ) );
        voter.setObjectIdentityRetrievalStrategy( new ObjectIdentityRetrievalStrategyImpl() );
        voter.setSidRetrievalStrategy( new SidRetrievalStrategyImpl() );
        voter.setProcessDomainObjectClass( Securable.class );
        ca = mock( ConfigAttribute.class );
        when( ca.getAttribute() ).thenReturn( "ACL_SECURABLE_COLLECTION_READ" );
        auth = new TestingAuthenticationToken( "bob", "1234" );
    }

    @Test
    public void testWhenCollectionContainNullOrIncompatibleEntries() {
        Acl acl = mock( Acl.class );
        when( acl.isGranted( any(), any(), anyBoolean() ) ).thenReturn( true );
        when( aclService.readAclsById( any() ) )
            .thenAnswer( a -> a.getArgument( 0, Collection.class ).stream()
                .distinct()
                .collect( Collectors.toMap( o -> ( ObjectIdentity ) o, o -> acl ) ) );
        Collection<?> collection = Arrays.asList( mock( Securable.class ), null, mock( Securable.class ) );
        Collection<?> result = ( Collection<?> ) voter.decide( auth, null, Collections.singletonList( ca ), collection );
        assertSame( collection, result );
        assertEquals( 3, result.size() );
        verify( acl, times( 2 ) ).isGranted( any(), any(), eq( false ) );
        verifyNoMoreInteractions( acl );
    }
}