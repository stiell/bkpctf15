module Main where
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Maybe
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Data.Array
import Data.Graph
import Data.Int
import Data.Monoid
import Data.List
import Data.List.Split
import Data.Serialize
import Data.Tuple
import Network.Simple.TCP
import qualified Data.ByteString as BS

readColours :: String -> Table Int
readColours s = listArray (0, length l - 1) l
	where l = map (read . last . splitOn ": ") $ lines s

recvAll :: Socket -> Int -> MaybeT IO BS.ByteString
recvAll s n = do
	b <- MaybeT $ recv s n
	let n' = n - BS.length b
	if n' == 0
		then return b
		else (b <>) <$> recvAll s n'

encrypt :: AES128 -> BS.ByteString -> BS.ByteString
encrypt = ecbEncrypt

proveColours :: Int -> Table Int -> Socket -> IO BS.ByteString
proveColours 0 c s = do
	mb <- recv s 1024
	case mb of
			Just b -> proveColours 0 c s >>= \b' -> return $ b <> b'
			_      -> return BS.empty
proveColours n c s = do
	let k = BS.replicate 16 42
	    CryptoPassed kc = cipherInit k
	    nc = (1 -) . uncurry (-) $ bounds c
	    ciphers = [encrypt kc $ BS.singleton (fromIntegral n) <> BS.replicate 15 0 {-encode (0 :: Int64, 0x30 + fromIntegral n :: Int64)-} | n <- elems c]
	sendMany s ciphers
	runMaybeT $ recvAll s 8
	send s k
	send s k
	print n
	proveColours (n - 1) c s
	
main :: IO ()
main = do
	c <- readColours <$> readFile "colors.txt"
	putStrLn "Connecting"
	f <- connect "52.86.232.163" "32794" $ \(s, remote) -> do
		putStrLn "Connected"
		putStrLn $ "Connection established to verifier at " ++ show remote
		proveColours 1000 c s
	print f
