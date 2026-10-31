-- The same milestone as tests/hello.lua, but every global is resolved through
-- the chunk's own environment table. Run it with:
--
--   .\out\Vesper.exe --exec vesper\tests\hello-globals.lua
--
-- A nil `print` or a nil `game` here means the environment table did not reach
-- the closure -- see docs/hostapi-11f1.md, "sandbox".
print("vesper: hello from the place")
print("vesper: place id =", game.PlaceId)
print("vesper: players =", #game:GetService("Players"):GetPlayers())
print("vesper: workspace children =", #workspace:GetChildren())
print("vesper: sum =", 21 + 21)
return "vesper-ok"