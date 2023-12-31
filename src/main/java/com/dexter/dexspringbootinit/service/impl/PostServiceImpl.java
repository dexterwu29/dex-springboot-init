package com.dexter.dexspringbootinit.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.dexter.dexspringbootinit.mapper.PostMapper;
import com.dexter.dexspringbootinit.model.entity.Post;
import com.dexter.dexspringbootinit.service.PostService;
import org.springframework.stereotype.Service;

/**
* @author lenovo
* @description 针对表【post(帖子)】的数据库操作Service实现
* @createDate 2023-12-31 10:22:06
*/
@Service
public class PostServiceImpl extends ServiceImpl<PostMapper, Post>
    implements PostService {

}




