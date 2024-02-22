package test.kim;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Transactional
public class InitService {

    private final EntityManager em;

    public void init() {
        User user = new User();
        user.setUsername("kim");

        em.persist(user);
    }
}
