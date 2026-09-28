UPDATE zm.Config SET Value='1' WHERE Name='ZM_OPT_USE_AUTH';
INSERT IGNORE INTO zm.Users (Username,Password,Name,Email,Phone,`Language`,Enabled,Stream,Events,Control,Monitors,Groups,Devices,Snapshots,`System`,MaxBandwidth,TokenMinExpiry,APIEnabled,HomeView,RoleId) VALUES
	 ('admin','$2b$12$NHZsm6AM2f2LQVROriz79ul3D6DnmFiZC.ZK5eqbF.ZWfwH9bqUJ6','','','','',1,'View','Edit','Edit','Create','Edit','Edit','Edit','Edit','',0,1,'',NULL),
	 ('lowpriv','$2y$10$Yne3H2/vT.zWA0ppbumj.uP96a9z3e3IaTp..Qxg55gFxq5tI/XDm','lowpriv','','','',1,'View','View','View','View','None','None','None','View','',0,1,'console',NULL),
	 ('medpriv','$2y$10$NsMAo4pC8aE2tQCWo0WcPeH/8A76d7EDgTzc.burQMQnJ1BoMzPei','medpriv','','','',1,'View','Edit','View','Create','View','View','None','View','',0,1,'console',NULL);
