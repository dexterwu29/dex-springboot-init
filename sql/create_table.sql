-- 创建库
create database if not exists my_db;

-- 切换库
use my_db;

-- 用户表
create table if not exists user
(
    id           bigint auto_increment comment 'id' primary key,
    userAccount  varchar(256)                                                                                not null comment '账号',
    userPassword varchar(512)                                                                                not null comment '密码',
    accessKey    varchar(512)                                                                                not null comment 'accessKey',
    secretKey    varchar(512)                                                                                not null comment 'secretKey',
    userName     varchar(256)  default '游客'                                                                  null comment '用户昵称',
    userAvatar   varchar(1024) default 'https://gw.alipayobjects.com/zos/rmsportal/BiazfanxmamNRoxxVxka.png' null comment '用户头像',
    userProfile  varchar(512)                                                                                null comment '用户简介',
    userRole     varchar(256)  default 'user'                                                                not null comment '用户角色：user/admin/ban',
    createTime   datetime      default CURRENT_TIMESTAMP                                                     not null comment '创建时间',
    updateTime   datetime      default CURRENT_TIMESTAMP                                                     not null on update CURRENT_TIMESTAMP comment '更新时间',
    isDelete     tinyint       default 0                                                                     not null comment '是否删除',
    index idx_userAccount (userAccount)
) comment '用户' collate = utf8mb4_unicode_ci;

-- 帖子表
create table if not exists post
(
    id         bigint auto_increment comment 'id' primary key,
    title      varchar(512)                       null comment '标题',
    content    text                               null comment '内容',
    tags       varchar(1024)                      null comment '标签列表（json 数组）',
    thumbNum   int      default 0                 not null comment '点赞数',
    favourNum  int      default 0                 not null comment '收藏数',
    userId     bigint                             not null comment '创建用户 id',
    createTime datetime default CURRENT_TIMESTAMP not null comment '创建时间',
    updateTime datetime default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '更新时间',
    isDelete   tinyint  default 0                 not null comment '是否删除',
    index idx_userId (userId)
) comment '帖子' collate = utf8mb4_unicode_ci;

-- 用户表，不用模拟数据，直接注册
