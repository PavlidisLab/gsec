package gemma.gsec.acl;

import gemma.gsec.acl.domain.AclService;
import gemma.gsec.acl.domain.*;
import gemma.gsec.model.Securable;
import gemma.gsec.model.SecuredChild;
import gemma.gsec.model.SecuredNotChild;
import org.aspectj.lang.JoinPoint;
import org.hibernate.SessionFactory;
import org.junit.Test;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.orm.hibernate4.HibernateTransactionManager;
import org.springframework.orm.hibernate4.LocalSessionFactoryBean;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;
import org.springframework.transaction.PlatformTransactionManager;

import javax.annotation.Nullable;
import javax.persistence.*;
import javax.sql.DataSource;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

@ContextConfiguration
public class AclAdviceTest extends AbstractTransactionalJUnit4SpringContextTests {

    @Configuration
    static class AclAdviceTestContextConfiguration {

        @Bean
        public DataSource dataSource() {
            return new SimpleDriverDataSource( new org.h2.Driver(), "jdbc:h2:mem:gsec;MODE=MYSQL;DB_CLOSE_DELAY=-1" );
        }

        @Bean
        public FactoryBean<SessionFactory> sessionFactory( DataSource dataSource ) {
            LocalSessionFactoryBean factory = new LocalSessionFactoryBean();
            factory.getHibernateProperties().setProperty( "hibernate.hbm2ddl.auto", "create" );
            factory.getHibernateProperties().setProperty( "hibernate.dialect", org.hibernate.dialect.H2Dialect.class.getName() );
            factory.getHibernateProperties().setProperty( "hibernate.cache.use_second_level_cache", "false" );
            factory.setDataSource( dataSource );
            factory.setConfigLocation( new ClassPathResource( "/gemma/gsec/hibernate.cfg.xml" ) );
            factory.setAnnotatedClasses( Parent.class, Child.class, ChildWithoutKnownParentOnCreate.class, InsecureChild.class );
            return factory;
        }

        @Bean
        public PlatformTransactionManager platformTransactionManager( SessionFactory sessionFactory ) {
            return new HibernateTransactionManager( sessionFactory );
        }

        @Bean
        public AclCache aclCache( AclAuthorizationStrategy aclAuthorizationStrategy, PermissionGrantingStrategy permissionGrantingStrategy ) {
            return new SpringCacheBasedAclCache( new ConcurrentMapCache( "test" ), permissionGrantingStrategy, aclAuthorizationStrategy );
        }

        @Bean
        public PermissionGrantingStrategy permissionGrantingStrategy( AuditLogger auditLogger ) {
            return new DefaultPermissionGrantingStrategy( auditLogger );
        }

        @Bean
        public SidRetrievalStrategy sidRetrievalStrategy() {
            return new AclSidRetrievalStrategyImpl( new NullRoleHierarchy() );
        }

        @Bean
        public AclAuthorizationStrategy aclAuthorizationStrategy( SidRetrievalStrategy sidRetrievalStrategy ) {
            return new AclAuthorizationStrategyImpl( new GrantedAuthority[] { new SimpleGrantedAuthority( "GROUP_ADMIN" ), new SimpleGrantedAuthority( "GROUP_ADMIN" ), new SimpleGrantedAuthority( "GROUP_ADMIN" ) }, sidRetrievalStrategy );
        }

        @Bean
        public ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy() {
            return new ObjectIdentityRetrievalStrategyImpl();
        }

        @Bean
        public AuditLogger auditLogger() {
            return new ConsoleAuditLogger();
        }

        @Bean
        public AclDao aclDao( SessionFactory sessionFactory, AclAuthorizationStrategy aclAuthorizationStrategy, AclCache aclCache ) {
            return new AclDaoImpl( sessionFactory, aclAuthorizationStrategy, aclCache );
        }

        @Bean
        public MutableAclService aclService( AclDao aclDao ) {
            return new AclServiceImpl( aclDao );
        }

        @Bean
        public AclAdvice aclAdvice( MutableAclService aclService, SessionFactory sessionFactory, ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy ) {
            return new AclAdvice( aclService, sessionFactory, objectIdentityRetrievalStrategy );
        }
    }

    @Entity
    class Parent implements Securable {

        @Id
        @GeneratedValue
        private Long id;
        @OneToMany(cascade = CascadeType.ALL)
        private Set<Child> child = new HashSet<>();
        @ManyToOne(cascade = CascadeType.ALL)
        private InsecureChild insecureChild;

        @Override
        public Long getId() {
            return id;
        }
    }

    @Entity
    class Child implements SecuredChild {

        @Id
        @GeneratedValue
        private Long id;

        @ManyToOne
        private Parent parent;

        @Override
        public Long getId() {
            return id;
        }

        @Nullable
        @Override
        public Securable getSecurityOwner() {
            return parent;
        }
    }

    @Entity
    static
    class ChildWithoutKnownParentOnCreate implements SecuredChild {

        @Id
        @GeneratedValue
        private Long id;

        @Override
        public Long getId() {
            return id;
        }
    }

    @Entity
    static
    class InsecureChild implements SecuredNotChild {

        @Id
        @GeneratedValue
        private Long id;

        @Override
        public Long getId() {
            return id;
        }
    }

    @Autowired
    private AclAdvice advice;

    @Autowired
    private AclService aclService;

    @Autowired
    private SessionFactory sessionFactory;

    @Test
    public void test() {
        authenticate( "GROUP_ADMIN" );
        Parent parent = new Parent();
        parent.child.add( new Child() );
        parent.insecureChild = new InsecureChild();
        sessionFactory.getCurrentSession().persist( parent );
        JoinPoint jp = mock( JoinPoint.class );
        advice.doCreateAdvice( jp, parent );

        Acl acl = readAcl( parent );
        assertNull( acl.getParentAcl() );
        assertEquals( new AclPrincipalSid( "bob" ), acl.getOwner() );

        Child firstChild = parent.child.iterator().next();
        Acl childAcl = readAcl( firstChild );
        assertEquals( acl, childAcl.getParentAcl() );
        assertEquals( new AclPrincipalSid( "bob" ), childAcl.getOwner() );
        assertTrue( acl.getEntries().isEmpty() );

        Acl insecureChildAcl = readAcl( parent.insecureChild );
        assertNull( insecureChildAcl.getParentAcl() );
        assertEquals( new AclPrincipalSid( "bob" ), insecureChildAcl.getOwner() );
    }

    public void authenticate( String... authorities ) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication( new TestingAuthenticationToken( "bob", "1234", authorities ) );
        SecurityContextHolder.setContext( context );
    }

    private Acl readAcl( Securable securable ) {
        return aclService.readAclById( new AclObjectIdentity( securable ) );
    }
}