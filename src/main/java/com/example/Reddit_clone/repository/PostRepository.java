package com.example.Reddit_clone.repository;


import com.example.Reddit_clone.model.Post;
import com.example.Reddit_clone.model.Subreddit;
import com.example.Reddit_clone.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostRepository extends JpaRepository<Post, Long> {
    List<Post> findAllBySubreddit(Subreddit subreddit);

    List<Post> findByUser(User user);
}
