package gemma.gsec.acl.domain;

import gemma.gsec.model.Securable;
import org.hibernate.SessionFactory;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;

@ContextConfiguration(locations = { "classpath*:gemma/gsec/applicationContext-*.xml", "classpath:gemma/gsec/testContext.xml" })
public class AclDaoTest extends AbstractTransactionalJUnit4SpringContextTests {

    @Autowired
    private AclDao aclDao;

    @Autowired
    private SessionFactory sessionFactory;

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

    @Test
    public void testFindObjectIdentityById() {
        AclObjectIdentity oid = new AclObjectIdentity( MyModel.class, 1L );
        oid.setOwnerSid( aclDao.createSid( new AclPrincipalSid( "me" ) ) );
        oid = aclDao.createObjectIdentity( oid );
        assertNotNull( oid.getId() );
        assertSame( oid, aclDao.findObjectIdentity( oid ) ); // by ID
        assertSame( oid, aclDao.findObjectIdentity( new AclObjectIdentity( MyModel.class, 1L ) ) ); // by natural ID
    }
}