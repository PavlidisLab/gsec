package gemma.gsec.acl.domain;

import gemma.gsec.model.Securable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.*;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.*;

@ContextConfiguration(locations = { "classpath*:gemma/gsec/applicationContext-*.xml", "classpath:gemma/gsec/testContext.xml" })
public class AclServiceTest extends AbstractJUnit4SpringContextTests {

    @Autowired
    private AclService aclService;

    public static class MyModel implements Securable {

        private final Long id;

        public MyModel( Long id ) {
            this.id = id;
        }

        @Override
        public Long getId() {
            return id;
        }
    }

    @Before
    public void setUpAuthentication() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication( new TestingAuthenticationToken( "admin", "1234", "GROUP_ADMIN" ) );
        SecurityContextHolder.setContext( context );
    }

    @After
    public void clearAuthentication() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void test() {
        AclSid me = new AclPrincipalSid( "me" );
        AclObjectIdentity oid = new AclObjectIdentity( new MyModel( 1L ) );

        MutableAcl acl = aclService.createAcl( oid );
        assertNotNull( oid.getId() );
        assertEquals( oid, acl.getObjectIdentity() );
        assertEquals( new AclPrincipalSid( "admin" ), acl.getOwner() );
        assertFalse( acl.isEntriesInheriting() );

        Acl reloadedAcl = aclService.readAclById( oid );
        assertNotNull( reloadedAcl.getOwner() );

        acl.insertAce( 0, BasePermission.READ, me, false );
        acl.setEntriesInheriting( true );
        aclService.updateAcl( acl );

        reloadedAcl = aclService.readAclById( oid );
        assertNotNull( reloadedAcl.getOwner() );
        assertTrue( reloadedAcl.isEntriesInheriting() );
        assertEquals( 1, reloadedAcl.getEntries().size() );
        AccessControlEntry entry = reloadedAcl.getEntries().iterator().next();
        assertNotNull( entry.getId() );
        assertSame( reloadedAcl, entry.getAcl() );
        assertNotNull( entry.getSid() );
        assertEquals( BasePermission.READ, entry.getPermission() );

        acl.deleteAce( 0 );
        aclService.updateAcl( acl );

        reloadedAcl = aclService.readAclById( oid );
        assertNotNull( reloadedAcl.getOwner() );
        assertTrue( reloadedAcl.getEntries().isEmpty() );
    }

    @Test
    public void testAclWithParent() {
        AclObjectIdentity oid = new AclObjectIdentity( new MyModel( 2L ) );
        MutableAcl acl = aclService.createAcl( oid );

        AclObjectIdentity oidP = new AclObjectIdentity( new MyModel( 3L ) );
        MutableAcl parentAcl = aclService.createAcl( oidP );

        acl.setParent( parentAcl );
        aclService.updateAcl( acl );

        assertThatThrownBy( () -> aclService.deleteAcl( oidP, false ) )
            .isInstanceOf( ChildrenExistException.class );

        // now, properly delete
        aclService.deleteAcl( oid, false );
        aclService.deleteAcl( oidP, false );

        assertThatThrownBy( () -> aclService.readAclById( new AclObjectIdentity( new MyModel( 3L ) ) ) )
            .isInstanceOf( NotFoundException.class );
        assertThatThrownBy( () -> aclService.readAclById( new AclObjectIdentity( new MyModel( 2L ) ) ) )
            .isInstanceOf( NotFoundException.class );
    }

    @Test
    public void testAclWithParentOnCreation() {
        AclObjectIdentity oidP = new AclObjectIdentity( new MyModel( 3L ) );
        MutableAcl parentAcl = aclService.createAcl( oidP );
        assertNotNull( oidP.getId() );

        AclObjectIdentity oid = new AclObjectIdentity( new MyModel( 2L ) );
        oid.setParentObject( new AclObjectIdentity( new MyModel( 3L ) ) );
        MutableAcl acl = aclService.createAcl( oid );

        assertEquals( parentAcl, acl.getParentAcl() );
    }

    @Test
    public void testAclWithParentDeleteChildren() {
        AclObjectIdentity oid = new AclObjectIdentity( new MyModel( 4L ) );
        MutableAcl acl = aclService.createAcl( oid );

        AclObjectIdentity oidP = new AclObjectIdentity( new MyModel( 5L ) );
        MutableAcl parentAcl = aclService.createAcl( oidP );

        acl.setParent( parentAcl );
        aclService.updateAcl( acl );

        aclService.deleteAcl( oidP, true );
        assertThatThrownBy( () -> aclService.readAclById( new AclObjectIdentity( new MyModel( 5L ) ) ) )
            .isInstanceOf( NotFoundException.class );
        assertThatThrownBy( () -> aclService.readAclById( new AclObjectIdentity( new MyModel( 4L ) ) ) )
            .isInstanceOf( NotFoundException.class );
    }

    @Test
    public void testCreateDuplicateAcl() {
        AclObjectIdentity oid = new AclObjectIdentity( new MyModel( 6L ) );
        aclService.createAcl( oid );
        assertNotNull( oid.getId() );
        // fast path, simply check the id
        assertThatThrownBy( () -> aclService.createAcl( oid ) )
            .isInstanceOf( AlreadyExistsException.class );
        // slow path, type & identifier are looked up
        assertThatThrownBy( () -> aclService.createAcl( new AclObjectIdentity( new MyModel( 6L ) ) ) )
            .isInstanceOf( AlreadyExistsException.class );
    }
}