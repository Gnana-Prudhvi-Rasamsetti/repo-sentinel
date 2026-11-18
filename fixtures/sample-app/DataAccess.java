class DataAccess {
    Object findUser(String userId) {
        return entityManager.createQuery("from User u where u.id = " + userId);
    }
}
