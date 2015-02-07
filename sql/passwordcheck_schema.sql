#
# Table structure for table `ezpassword_history`
#

DROP TABLE IF EXISTS `ezpassword_history`;
CREATE TABLE `ezpassword_history` (
  `id` int(11) NOT NULL auto_increment,
  `user_id` int(11) NOT NULL default '0',
  `password_hash` varchar(50) NULL default '',
  `password_hash_type` int(11) NOT NULL default '2',
  `password_fails` int(11) NOT NULL default '0',
  `timestamp` int(11) NOT NULL default '0',
  PRIMARY KEY  (`id`)
);

