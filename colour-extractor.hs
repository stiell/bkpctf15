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
import Data.Serialize
import Data.Tuple
import Network.Simple.TCP
import qualified Data.ByteString as BS

buildGraph es = buildG (0, maximum $ map snd es) (es <> map swap es)

affectedNeighbours c g v = filter (\n -> c ! n == 0) $ g ! v

updateColours c g [] = (c, [])
updateColours c g (v : vs) = let
	(c', f1) = case (c ! v, [1, 2, 3] \\ map (c !) (g ! v)) of
			(0, [n]) -> addColour c g v n
			_        -> (c, [v])
	(c'', f2) = updateColours c' g vs
	in (c'', filter ((0 ==) . (c'' !)) f1 <> f2)

addColour c g v n = let c' = c // [(v, n)]
                    in updateColours c' g (affectedNeighbours c' g v)

readGraph :: String -> Graph
readGraph = buildGraph . map ((\[a, b] -> (a, b)) . map read . words) . filter (('#' /=) . head) . lines

recvAll :: Socket -> Int -> MaybeT IO BS.ByteString
recvAll s n = do
	b <- MaybeT $ recv s n
	let n' = n - BS.length b
	if n' == 0
		then return b
		else (b <>) <$> recvAll s n'

recvCiphers :: Socket -> Int -> MaybeT IO [BS.ByteString]
recvCiphers s n = replicateM n $ recvAll s 16

sendVertices :: Socket -> Vertex -> Vertex -> IO ()
sendVertices s a b = send s $ encode (fromIntegral a :: Int32, fromIntegral b :: Int32)

recvKeys :: Socket -> MaybeT IO (AES128, AES128)
recvKeys s = do
	a <- gc
	b <- gc
	return (a, b)
	where gc = do
		k <- recvAll s 16
		case cipherInit k of
			CryptoPassed c -> return c
			_              -> mzero

decrypt :: AES128 -> BS.ByteString -> BS.ByteString
decrypt = ecbDecrypt

resolveColours :: Table Int -> Graph -> [Vertex] -> Socket -> IO (Table Int)
resolveColours c _ [] _ = return c
resolveColours c g (v : f) s = do
	putStrLn "Extracting colour from prover"
	let nc = (1 -) . uncurry (-) $ bounds c
	    n1 = head $ filter ((0 /=) . (c !)) (g ! v)
	    n2 = head $ filter ((\n -> n /= 0 && n /= c ! n1) . (c !)) (g ! n1)
	mn <- runMaybeT $ do
		ciphers <- recvCiphers s nc
		liftIO $ sendVertices s v n2
		(kv, kn2) <- recvKeys s
		return $ if decrypt kv (ciphers !! v) == decrypt kn2 (ciphers !! n2) then c ! n2 else head ([1, 2, 3] \\ [c ! n2, c ! n1])
	case mn of
		Just n -> do
			let (c', f') = addColour c g v n
			putStrLn $ "v_" <> show v <> (if n == c ! n2 then " =" else " /") <> "= v_" <> show n2
			putStrLn $ show (length . filter (0 /=) $ elems c') <> " of " <> show nc <> " vertices coloured"
			resolveColours c' g (filter ((0 ==) . (c' !)) f <> f') s
		_      -> do
			putStrLn "Server closed the connection early"
			return c

showColours :: Table Int -> String
showColours = unlines . map (\(i, e) -> show i <> ": " <> show e) . assocs

main :: IO ()
main = do
	g <- readGraph <$> readFile "graph.txt"
	let c = 0 <$ g
	    (c', f) = addColour c g 0 1
	    (c'', f') = addColour c' g (head f) 2
	c''' <- connect "52.86.232.163" "32795" $ \(s, remote) -> do
		putStrLn $ "Connection established to prover at " ++ show remote
		resolveColours c'' g f' s
	writeFile "colors.txt" $ showColours c'''
	putStrLn "Data written to colors.txt"
