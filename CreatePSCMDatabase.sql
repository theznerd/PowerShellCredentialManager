USE master;
GO

CREATE DATABASE PSCM
GO

USE [PSCM]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[SecureCredentials](
	[CredentialPurpose] [nvarchar](256) NOT NULL,
	[EncryptedUsername] [nvarchar](max) NULL,
	[EncryptedPassword] [nvarchar](max) NOT NULL,
	[CertificateThumbprint] [nvarchar](256) NOT NULL,
 CONSTRAINT [PK_SecureCredentials] PRIMARY KEY CLUSTERED 
(
	[CredentialPurpose] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY],
UNIQUE NONCLUSTERED 
(
	[CredentialPurpose] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO