CREATE OR REPLACE FUNCTION is_rfc1918block(block cidr)
RETURNS boolean
LANGUAGE plpgsql
AS
$$
BEGIN
  RETURN
    ('192.168.0.0/16' >>= block)
    OR ('172.16.0.0/12' >>= block)
    OR ('10.0.0.0/8' >>= block);
END;
$$